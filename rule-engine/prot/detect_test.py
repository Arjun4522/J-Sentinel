import yaml
import json
import logging
import argparse
import subprocess
import tempfile
import re
import os
import sys
from pathlib import Path
from typing import List, Dict, Any, Optional, Set, Tuple, Union
from dataclasses import dataclass, asdict
from datetime import datetime
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from multiprocessing import cpu_count
from collections import defaultdict, Counter
import hashlib
import time

# Configure logging with proper formatting
class ColoredFormatter(logging.Formatter):
    """Custom formatter with color support"""

    COLORS = {
        "DEBUG": "\033[36m",  # Cyan
        "INFO": "\033[32m",  # Green
        "WARNING": "\033[33m",  # Yellow
        "ERROR": "\033[31m",  # Red
        "CRITICAL": "\033[35m",  # Magenta
        "RESET": "\033[0m",  # Reset
    }

    def format(self, record):
        color = self.COLORS.get(record.levelname, self.COLORS["RESET"])
        reset = self.COLORS["RESET"]
        record.levelname = f"{color}{record.levelname}{reset}"
        return super().format(record)


# Setup logging
def setup_logging(verbose: bool = False, log_file: Optional[Path] = None):
    """Configure logging with both console and file handlers"""
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)

    # Clear existing handlers
    logger.handlers.clear()

    # Console handler with colors
    console_handler = logging.StreamHandler(sys.stdout)
    console_formatter = ColoredFormatter(
        "%(asctime)s | %(levelname)s | %(name)s | %(message)s", datefmt="%H:%M:%S"
    )
    console_handler.setFormatter(console_formatter)
    console_handler.setLevel(logging.DEBUG if verbose else logging.INFO)
    logger.addHandler(console_handler)

    # File handler if specified
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_formatter = logging.Formatter(
            "%(asctime)s | %(levelname)s | %(name)s | %(funcName)s:%(lineno)d | %(message)s"
        )
        file_handler.setFormatter(file_formatter)
        file_handler.setLevel(logging.DEBUG)
        logger.addHandler(file_handler)


logger = logging.getLogger(__name__)


@dataclass
class Rule:
    """Represents a security detection rule"""

    id: str
    category: str
    type: str  # 'semgrep', 'regex', or 'graph'
    pattern: Union[Dict[str, Any], str, List[str]]
    severity: str
    description: str
    remediation: str
    language: str
    graph: str = "codegraph"
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None
    confidence: str = "HIGH"
    tags: List[str] = None

    def __post_init__(self):
        if self.tags is None:
            self.tags = []
        # Normalize severity
        self.severity = self.severity.upper()
        if self.severity not in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            self.severity = "MEDIUM"


@dataclass
class Vulnerability:
    """Represents a detected security vulnerability"""

    rule_id: str
    category: str
    severity: str
    location: str
    details: str
    remediation: str
    context: Dict[str, Any]
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None
    confidence: str = "HIGH"
    file_hash: Optional[str] = None
    line_number: int = 0
    column_number: int = 0
    code_snippet: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return asdict(self)


class LanguageDetector:
    """Advanced language detection utility"""

    LANGUAGE_PATTERNS = {
        "java": {
            "extensions": [".java"],
            "keywords": {
                "public",
                "private",
                "protected",
                "class",
                "interface",
                "package",
                "import",
            },
            "imports": {"java.", "javax.", "org.springframework"},
            "node_types": {"PACKAGE", "CLASS", "INTERFACE", "METHOD"},
            "data_types": {"String", "Integer", "List", "Map", "Set"},
        },
        "cpp": {
            "extensions": [".cpp", ".cc", ".cxx", ".c++", ".hpp", ".h", ".c"],
            "keywords": {"std::", "#include", "#define", "namespace", "using"},
            "imports": {"iostream", "vector", "string", "algorithm"},
            "node_types": {"FUNCTION", "STRUCT", "CLASS", "NAMESPACE"},
            "data_types": {"int", "char", "double", "float", "bool", "void"},
        },
        "python": {
            "extensions": [".py", ".py3", ".pyw"],
            "keywords": {"def", "class", "import", "from", "__init__", "if __name__"},
            "imports": {"os", "sys", "json", "requests", "flask", "django"},
            "node_types": {"FUNCTION_DEF", "CLASS_DEF", "IMPORT"},
            "data_types": {"str", "int", "list", "dict", "set"},
        },
        "javascript": {
            "extensions": [".js", ".jsx", ".ts", ".tsx", ".mjs"],
            "keywords": {
                "function",
                "var",
                "let",
                "const",
                "class",
                "import",
                "require",
            },
            "imports": {"require", "express", "react", "lodash", "axios"},
            "node_types": {
                "FUNCTION_DECLARATION",
                "CLASS_DECLARATION",
                "IMPORT_DECLARATION",
            },
            "data_types": {"string", "number", "boolean", "object", "array"},
        },
        "csharp": {
            "extensions": [".cs"],
            "keywords": {"using", "namespace", "class", "public", "private", "static"},
            "imports": {"System", "Microsoft", "Newtonsoft"},
            "node_types": {"CLASS", "METHOD", "NAMESPACE"},
            "data_types": {"string", "int", "bool", "double", "var"},
        },
    }

    @classmethod
    def detect_from_file(cls, file_path: Path) -> str:
        """Detect language from file path and content"""
        if not file_path.exists() or not file_path.is_file():
            return "unknown"

        ext = file_path.suffix.lower()

        # First check by extension
        for lang, patterns in cls.LANGUAGE_PATTERNS.items():
            if ext in patterns["extensions"]:
                return lang

        # If extension detection fails, analyze content
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read(1024)  # Read first 1KB for analysis
                return cls._analyze_content(content)
        except Exception as e:
            logger.debug(f"Error reading file {file_path}: {e}")
            return "unknown"

    @classmethod
    def detect_from_graph(cls, codegraph: Dict[str, Any]) -> str:
        """Detect language from code graph structure"""
        if not isinstance(codegraph, dict):
            return "unknown"

        # Check metadata first
        if "language" in codegraph:
            return codegraph["language"].lower()

        nodes = codegraph.get("nodes", [])
        if not nodes:
            return "unknown"

        # Extract features from nodes
        node_types = {n.get("type", "").upper() for n in nodes if n.get("type")}
        node_names = {n.get("name", "").lower() for n in nodes if n.get("name")}
        data_types = {n.get("dataType", "").lower() for n in nodes if n.get("dataType")}
        imports = {n.get("name", "") for n in nodes if n.get("type") == "IMPORT"}

        # Score each language
        scores = {}
        for lang, patterns in cls.LANGUAGE_PATTERNS.items():
            score = 0

            # Check node types
            if node_types & set(patterns["node_types"]):
                score += 3

            # Check imports/includes
            if any(
                imp_pattern in imp
                for imp in imports
                for imp_pattern in patterns["imports"]
            ):
                score += 2

            # Check keywords in names
            if node_names & patterns["keywords"]:
                score += 2

            # Check data types
            if data_types & patterns["data_types"]:
                score += 1

            scores[lang] = score

        # Return language with highest score
        if scores:
            detected_lang = max(scores, key=scores.get)
            if scores[detected_lang] > 0:
                return detected_lang

        return "none"

    @classmethod
    def _analyze_content(cls, content: str) -> str:
        """Analyze file content to detect language"""
        content_lower = content.lower()
        scores = {}

        for lang, patterns in cls.LANGUAGE_PATTERNS.items():
            score = 0
            for keyword in patterns["keywords"]:
                if keyword.lower() in content_lower:
                    score += content_lower.count(keyword.lower())
            scores[lang] = score

        if scores:
            detected_lang = max(scores, key=scores.get)
            if scores[detected_lang] > 0:
                return detected_lang

        return "none"


class VulnerabilityDetector:
    """Advanced vulnerability detection engine"""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.rules: Dict[str, List[Rule]] = defaultdict(list)
        self.graphs: Dict[str, Dict[str, Any]] = {}
        self.graph_languages: Dict[str, str] = {}
        self.vulnerabilities: List[Vulnerability] = []

        # Configuration
        self.source_dir = Path(config.get("source_dir", "."))
        self.graphs_dir = Path(config.get("graphs_dir", "graphs"))
        self.output_path = Path(config.get("output_path", "vulnerability_report.json"))
        self.rules_dir = Path(config.get("rules_dir", "rules"))
        self.max_workers = config.get("max_workers", min(cpu_count(), 8))
        self.timeout = config.get("timeout", 300)
        self.use_semgrep_registry = config.get("use_semgrep_registry", False)

        # Create default rules if rules directory doesn't exist
        if not self.rules_dir.exists():
            self._create_default_rules()

        # Statistics
        self.stats = {
            "files_processed": 0,
            "graphs_processed": 0,
            "rules_loaded": 0,
            "vulnerabilities_found": 0,
            "scan_start_time": None,
            "scan_end_time": None,
        }

        logger.info(
            f"Initialized VulnerabilityDetector with {self.max_workers} workers"
        )

    def _create_default_rules(self):
        """Create default security rules"""
        self.rules_dir.mkdir(parents=True, exist_ok=True)

        # Default rules for common vulnerabilities
        default_rules = {
            "python": [
                {
                    "id": "py-sql-injection",
                    "category": "Security",
                    "type": "regex",
                    "pattern": r'(execute|cursor\.execute|query)\s*\(\s*["\'].*%.*["\']',
                    "severity": "HIGH",
                    "description": "Potential SQL injection vulnerability",
                    "remediation": "Use parameterized queries",
                    "cwe_id": "CWE-89",
                    "owasp_category": "A03:2021",
                },
                {
                    "id": "py-command-injection",
                    "category": "Security",
                    "type": "regex",
                    "pattern": r"(os\.system|subprocess\.call|subprocess\.run|os\.popen)\s*\([^)]*\+",
                    "severity": "HIGH",
                    "description": "Potential command injection vulnerability",
                    "remediation": "Use subprocess with shell=False and validate inputs",
                    "cwe_id": "CWE-78",
                    "owasp_category": "A03:2021",
                },
            ],
            "java": [
                {
                    "id": "java-sql-injection",
                    "category": "Security",
                    "type": "regex",
                    "pattern": r'(executeQuery|executeUpdate|execute)\s*\(\s*["\'].*\+',
                    "severity": "HIGH",
                    "description": "Potential SQL injection vulnerability",
                    "remediation": "Use PreparedStatement with parameter binding",
                    "cwe_id": "CWE-89",
                    "owasp_category": "A03:2021",
                },
            ],
            "javascript": [
                {
                    "id": "js-xss",
                    "category": "Security",
                    "type": "regex",
                    "pattern": r"(innerHTML|outerHTML|document\.write)\s*=.*\+",
                    "severity": "MEDIUM",
                    "description": "Potential XSS vulnerability",
                    "remediation": "Sanitize user input before DOM insertion",
                    "cwe_id": "CWE-79",
                    "owasp_category": "A03:2021",
                },
            ],
        }

        for lang, rules in default_rules.items():
            lang_dir = self.rules_dir / lang
            lang_dir.mkdir(exist_ok=True)

            rules_file = lang_dir / "default.yaml"
            with open(rules_file, "w") as f:
                yaml.dump({"rules": rules}, f, default_flow_style=False)

        logger.info(f"Created default rules in {self.rules_dir}")

    def scan_codebase(self) -> Dict[str, Any]:
        """Main entry point for scanning codebase"""
        self.stats["scan_start_time"] = datetime.now()
        logger.info(f"Starting vulnerability scan of {self.source_dir}")

        try:
            # Discover files
            source_files = self._discover_source_files()
            if not source_files:
                logger.warning("No source files found to scan")
                return self._generate_report()

            logger.info(f"Found {len(source_files)} source files")

            # Process files in parallel
            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                future_to_file = {
                    executor.submit(self._process_file, file_path): file_path
                    for file_path in source_files
                }

                for future in as_completed(future_to_file):
                    file_path = future_to_file[future]
                    try:
                        vulnerabilities = future.result()
                        self.vulnerabilities.extend(vulnerabilities)
                        self.stats["files_processed"] += 1

                        if vulnerabilities:
                            logger.info(
                                f"Found {len(vulnerabilities)} vulnerabilities in {file_path}"
                            )

                    except Exception as e:
                        logger.error(f"Error processing {file_path}: {e}")

            self.stats["vulnerabilities_found"] = len(self.vulnerabilities)
            self.stats["scan_end_time"] = datetime.now()

            # Generate and save report
            report = self._generate_report()
            self._save_report(report)

            return report

        except Exception as e:
            logger.error(f"Error during codebase scan: {e}")
            raise

    def _discover_source_files(self) -> List[Path]:
        """Discover source files in the codebase"""
        source_files = []

        # Get all supported extensions
        all_extensions = set()
        for patterns in LanguageDetector.LANGUAGE_PATTERNS.values():
            all_extensions.update(patterns["extensions"])

        # Walk through source directory
        for root, dirs, files in os.walk(self.source_dir):
            # Skip common non-source directories
            dirs[:] = [
                d
                for d in dirs
                if not d.startswith(".")
                and d
                not in {
                    "node_modules",
                    "__pycache__",
                    "venv",
                    "env",
                    "build",
                    "dist",
                    "target",
                }
            ]

            for file in files:
                file_path = Path(root) / file
                if file_path.suffix.lower() in all_extensions:
                    source_files.append(file_path)

        return source_files

    def _process_file(self, file_path: Path) -> List[Vulnerability]:
        """Process a single source file"""
        vulnerabilities = []

        try:
            # Detect language
            language = LanguageDetector.detect_from_file(file_path)
            if language == "unknown":
                logger.debug(f"Unknown language for file: {file_path}")
                return vulnerabilities

            # Read file content
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
            except Exception as e:
                logger.error(f"Error reading file {file_path}: {e}")
                return vulnerabilities

            # Load local rules for this language
            rules = self.load_rules(language)
            if rules:
                logger.info(f"Applying {len(rules)} local rules for {language} to {file_path}")
                # Apply local rules
                for rule in rules:
                    try:
                        rule_vulns = self._apply_rule(rule, content, file_path, language)
                        vulnerabilities.extend(rule_vulns)
                    except Exception as e:
                        logger.error(f"Error applying rule {rule.id} to {file_path}: {e}")
            else:
                logger.debug(f"No local rules found for language: {language}")

            # If use_semgrep_registry is enabled, perform real-time Semgrep scan
            if self.use_semgrep_registry:
                logger.info(f"Performing real-time Semgrep scan for {language} on {file_path}")
                semgrep_vulns = self._realtime_semgrep_scan(language, content, file_path)
                vulnerabilities.extend(semgrep_vulns)

        except Exception as e:
            logger.error(f"Error processing file {file_path}: {e}")

        return vulnerabilities

    def _realtime_semgrep_scan(self, language: str, content: str, file_path: Path) -> List[Vulnerability]:
        """Perform real-time Semgrep scan using registry rules"""
        vulnerabilities = []

        try:
            # Create temporary file for Semgrep
            with tempfile.TemporaryDirectory() as tmpdir:
                ext = self._get_file_extension(language)
                temp_file = Path(tmpdir) / f"source{ext}"
                temp_file.write_text(content, encoding="utf-8")

                # Use p/c for both C and C++ files
                semgrep_config = "p/c" if language in ["cpp", "c"] else f"p/{language}"

                # Run Semgrep with registry rules
                cmd = [
                    "semgrep",
                    "--config",
                    semgrep_config,
                    "--json",
                    "--quiet",
                    "--timeout",
                    str(self.timeout),
                    str(temp_file),
                ]

                result = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=self.timeout, check=False
                )

                if result.stdout:
                    semgrep_output = json.loads(result.stdout)
                    vulnerabilities = self._parse_semgrep_output(semgrep_output, file_path)
                    logger.info(f"Found {len(vulnerabilities)} vulnerabilities in {file_path} via Semgrep")
                else:
                    logger.warning(f"No output from Semgrep scan for {language} on {file_path}: {result.stderr}")

        except subprocess.TimeoutExpired:
            logger.error(f"Semgrep scan timed out for {language} after {self.timeout} seconds")
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse Semgrep JSON output for {language}: {e}")
        except FileNotFoundError:
            logger.error("Semgrep not found. Install with: pip install semgrep")
        except Exception as e:
            logger.error(f"Error in Semgrep scan for {language}: {e}")

        return vulnerabilities

    def _apply_rule(
        self, rule: Rule, content: str, file_path: Path, language: str
    ) -> List[Vulnerability]:
        """Apply a single rule to content"""
        vulnerabilities = []

        if rule.type == "regex":
            vulnerabilities = self._apply_regex_rule(rule, content, file_path)
        elif rule.type == "semgrep":
            vulnerabilities = self._apply_semgrep_rule(
                rule, content, file_path, language
            )
        elif rule.type == "graph":
            # Graph rules would require code graph analysis
            logger.debug(f"Graph rule {rule.id} skipped (not implemented)")

        return vulnerabilities

    def _apply_regex_rule(
        self, rule: Rule, content: str, file_path: Path
    ) -> List[Vulnerability]:
        """Apply regex-based rule"""
        vulnerabilities = []

        try:
            pattern = rule.pattern
            if isinstance(pattern, dict):
                pattern = pattern.get("pattern", "")

            if not pattern:
                return vulnerabilities

            # Split content into lines for line number tracking
            lines = content.split("\n")

            for line_num, line in enumerate(lines, 1):
                matches = re.finditer(pattern, line, re.IGNORECASE)

                for match in matches:
                    location = f"{file_path.name}:{line_num}:{match.start() + 1}"
                    code_snippet = line.strip()

                    # Create vulnerability
                    vulnerability = Vulnerability(
                        rule_id=rule.id,
                        category=rule.category,
                        severity=rule.severity,
                        location=location,
                        details=rule.description,
                        remediation=rule.remediation,
                        context={
                            "file_path": str(file_path),
                            "match": match.group(),
                            "line": line.strip(),
                        },
                        cwe_id=rule.cwe_id,
                        owasp_category=rule.owasp_category,
                        confidence=rule.confidence,
                        file_hash=hashlib.md5(
                            f"{rule.id}:{location}".encode()
                        ).hexdigest(),
                        line_number=line_num,
                        column_number=match.start() + 1,
                        code_snippet=code_snippet,
                    )

                    vulnerabilities.append(vulnerability)

        except re.error as e:
            logger.error(f"Invalid regex pattern in rule {rule.id}: {e}")
        except Exception as e:
            logger.error(f"Error applying regex rule {rule.id}: {e}")

        return vulnerabilities

    def _apply_semgrep_rule(
        self, rule: Rule, content: str, file_path: Path, language: str
    ) -> List[Vulnerability]:
        """Apply Semgrep-based rule"""
        vulnerabilities = []

        try:
            # Create temporary files
            with tempfile.TemporaryDirectory() as tmpdir:
                # Create rule file
                rules_file = Path(tmpdir) / "rule.yaml"
                self._create_semgrep_rule_file(rule, rules_file)

                # Create source file
                ext = self._get_file_extension(language)
                source_file = Path(tmpdir) / f"source{ext}"
                source_file.write_text(content, encoding="utf-8")

                # Run Semgrep
                vulnerabilities = self._execute_semgrep(
                    rules_file, source_file, file_path, language
                )

        except Exception as e:
            logger.error(f"Error applying Semgrep rule {rule.id}: {e}")

        return vulnerabilities

    def _create_semgrep_rule_file(self, rule: Rule, rules_file: Path):
        """Create Semgrep rule file"""
        semgrep_rule = {
            "rules": [
                {
                    "id": rule.id,
                    "message": rule.description,
                    "severity": rule.severity.lower(),
                    "languages": [rule.language],
                    "metadata": {
                        "category": rule.category,
                        "cwe": rule.cwe_id,
                        "owasp": rule.owasp_category,
                        "confidence": rule.confidence,
                    },
                }
            ]
        }

        # Handle pattern structure
        if isinstance(rule.pattern, str):
            semgrep_rule["rules"][0]["pattern"] = rule.pattern
        elif isinstance(rule.pattern, list):
            semgrep_rule["rules"][0]["patterns"] = rule.pattern
        elif isinstance(rule.pattern, dict):
            semgrep_rule["rules"][0].update(rule.pattern)

        with open(rules_file, "w") as f:
            yaml.dump(semgrep_rule, f, default_flow_style=False)

    def _execute_semgrep(
        self, rules_file: Path, source_file: Path, original_file: Path, language: str
    ) -> List[Vulnerability]:
        """Execute Semgrep and parse results"""
        vulnerabilities = []

        try:
            cmd = [
                "semgrep",
                "--config",
                str(rules_file),
                "--json",
                "--quiet",
                "--timeout",
                str(self.timeout),
                str(source_file),
            ]

            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=self.timeout, check=False
            )

            if result.stdout:
                semgrep_output = json.loads(result.stdout)
                vulnerabilities = self._parse_semgrep_output(
                    semgrep_output, original_file
                )

        except subprocess.TimeoutExpired:
            logger.error(f"Semgrep analysis timed out after {self.timeout} seconds")
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse Semgrep JSON output: {e}")
        except FileNotFoundError:
            logger.error("Semgrep not found. Install with: pip install semgrep")
        except Exception as e:
            logger.error(f"Error executing Semgrep: {e}")

        return vulnerabilities

    def _parse_semgrep_output(
        self, semgrep_output: Dict[str, Any], original_file: Path
    ) -> List[Vulnerability]:
        """Parse Semgrep JSON output"""
        vulnerabilities = []

        for finding in semgrep_output.get("results", []):
            try:
                rule_id = finding.get("check_id", "unknown")

                # Location information
                start_pos = finding.get("start", {})
                line_num = start_pos.get("line", 0)
                col_num = start_pos.get("col", 0)
                location = f"{original_file.name}:{line_num}:{col_num}"

                # Extract metadata
                extra = finding.get("extra", {})
                metadata = extra.get("metadata", {})

                # Get code snippet
                code_snippet = extra.get("lines", "")

                # Handle CWE and OWASP fields that might be lists
                cwe_id = metadata.get("cwe")
                if isinstance(cwe_id, list):
                    cwe_id = cwe_id[0] if cwe_id else None

                owasp_category = metadata.get("owasp")
                if isinstance(owasp_category, list):
                    owasp_category = owasp_category[0] if owasp_category else None

                vulnerability = Vulnerability(
                    rule_id=rule_id,
                    category=metadata.get("category", "Security"),
                    severity=extra.get("severity", "medium").upper(),
                    location=location,
                    details=extra.get("message", "No description"),
                    remediation=metadata.get("remediation", "No remediation provided"),
                    context={
                        "file_path": str(original_file),
                        "code": code_snippet,
                        "semgrep_finding": finding,
                    },
                    cwe_id=cwe_id,
                    owasp_category=owasp_category,
                    confidence=metadata.get("confidence", "HIGH"),
                    file_hash=hashlib.md5(f"{rule_id}:{location}".encode()).hexdigest(),
                    line_number=line_num,
                    column_number=col_num,
                    code_snippet=code_snippet,
                )

                vulnerabilities.append(vulnerability)

            except Exception as e:
                logger.error(f"Error parsing Semgrep finding: {e}")

        return vulnerabilities

    def _get_file_extension(self, language: str) -> str:
        """Get file extension for language"""
        ext_map = {
            "python": ".py",
            "java": ".java",
            "javascript": ".js",
            "cpp": ".cpp",
            "c": ".c",
            "csharp": ".cs",
        }
        return ext_map.get(language, ".txt")

    def load_rules(self, language: str) -> List[Rule]:
        if language in self.rules:
            return self.rules[language]

        rules = []
        lang_rules_dir = self.rules_dir / language

        if not lang_rules_dir.exists():
            logger.debug(f"No rules directory for language: {language}")
            return rules

        # Recursively find all YAML files in subdirectories
        rule_files = list(lang_rules_dir.rglob("*.yaml")) + list(lang_rules_dir.rglob("*.yml"))

        for rule_file in rule_files:
            try:
                with open(rule_file, "r") as f:
                    rule_data = yaml.safe_load(f)
                if "rules" in rule_data:
                    for rule_dict in rule_data["rules"]:
                        rule = self._create_rule_from_dict(rule_dict, language)
                        if rule:
                            rules.append(rule)
            except Exception as e:
                logger.error(f"Error loading rule file {rule_file}: {e}")

        self.rules[language] = rules
        self.stats["rules_loaded"] += len(rules)
        return rules

    def _create_rule_from_dict(
        self, rule_dict: Dict[str, Any], language: str
    ) -> Optional[Rule]:
        """Create Rule object from dictionary"""
        try:
            return Rule(
                id=rule_dict.get("id", "unknown"),
                category=rule_dict.get("category", "Security"),
                type=rule_dict.get("type", "semgrep"),  # Default to semgrep for registry rules
                pattern=rule_dict.get("pattern", {}),
                severity=rule_dict.get("severity", "MEDIUM"),
                description=rule_dict.get("message", "No description"),
                remediation=rule_dict.get("fix", "No remediation provided"),
                language=language,
                cwe_id=rule_dict.get("cwe"),
                owasp_category=rule_dict.get("owasp"),
                confidence=rule_dict.get("confidence", "HIGH"),
                tags=rule_dict.get("tags", []),
            )
        except Exception as e:
            logger.error(f"Error creating rule from dict: {e}")
            return None

    def _generate_report(self) -> Dict[str, Any]:
        """Generate final vulnerability report"""
        scan_duration = None
        if self.stats["scan_start_time"] and self.stats["scan_end_time"]:
            scan_duration = (
                self.stats["scan_end_time"] - self.stats["scan_start_time"]
            ).total_seconds()

        # Group vulnerabilities by severity
        severity_counts = Counter(v.severity for v in self.vulnerabilities)

        # Group by category
        category_counts = Counter(v.category for v in self.vulnerabilities)

        # Group by file
        file_counts = Counter(v.location.split(":")[0] for v in self.vulnerabilities)

        report = {
            "scan_info": {
                "scan_id": str(uuid.uuid4()),
                "timestamp": datetime.now().isoformat(),
                "source_directory": str(self.source_dir),
                "scan_duration_seconds": scan_duration,
                "total_files_processed": self.stats["files_processed"],
                "total_rules_loaded": self.stats["rules_loaded"],
                "total_vulnerabilities": len(self.vulnerabilities),
            },
            "summary": {
                "severity_breakdown": dict(severity_counts),
                "category_breakdown": dict(category_counts),
                "files_with_issues": len(file_counts),
                "top_vulnerable_files": dict(file_counts.most_common(10)),
            },
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
            "recommendations": self._generate_recommendations(),
            "compliance": self._generate_compliance_report(),
        }

        logger.info(
            f"Generated report with {len(self.vulnerabilities)} vulnerabilities"
        )
        return report

    def _generate_recommendations(self) -> List[Dict[str, Any]]:
        """Generate security recommendations based on findings"""
        recommendations = []

        # Severity-based recommendations
        severity_counts = Counter(v.severity for v in self.vulnerabilities)

        if severity_counts.get("CRITICAL", 0) > 0:
            recommendations.append(
                {
                    "priority": "URGENT",
                    "recommendation": "Address critical vulnerabilities immediately as they pose the highest risk",
                    "action_items": [
                        "Review all CRITICAL severity findings",
                        "Implement fixes following remediation guidance",
                        "Conduct security review before deployment",
                    ],
                }
            )

        if severity_counts.get("HIGH", 0) > 0:
            recommendations.append(
                {
                    "priority": "HIGH",
                    "recommendation": "Address high severity vulnerabilities promptly",
                    "action_items": [
                        "Review all HIGH severity findings",
                        "Schedule fixes for next release",
                        "Consider additional security testing",
                    ],
                }
            )

        # Category-based recommendations
        category_counts = Counter(v.category for v in self.vulnerabilities)

        if "SQL Injection" in category_counts:
            recommendations.append(
                {
                    "priority": "HIGH",
                    "recommendation": "Implement SQL injection prevention measures",
                    "action_items": [
                        "Use parameterized queries or prepared statements",
                        "Implement ORM with built-in protection",
                        "Conduct security training on SQLi risks",
                    ],
                }
            )

        if "XSS" in category_counts:
            recommendations.append(
                {
                    "priority": "MEDIUM",
                    "recommendation": "Implement XSS protection",
                    "action_items": [
                        "Use output encoding for dynamic content",
                        "Implement Content Security Policy (CSP)",
                        "Validate and sanitize all user input",
                    ],
                }
            )

        # General recommendations
        if len(self.vulnerabilities) > 0:
            recommendations.append(
                {
                    "priority": "GENERAL",
                    "recommendation": "Improve secure coding practices",
                    "action_items": [
                        "Conduct security code reviews",
                        "Implement static analysis in CI/CD pipeline",
                        "Provide secure coding training for developers",
                    ],
                }
            )

        return recommendations

    def _generate_compliance_report(self) -> Dict[str, Any]:
        """Generate compliance report based on findings"""
        standards = {
            "OWASP": {"covered": 0, "total": 0, "categories": defaultdict(int)},
            "CWE": {"covered": 0, "total": 0, "weaknesses": defaultdict(int)},
        }

        # Count OWASP and CWE coverage
        owasp_categories = set()
        cwe_ids = set()

        for vuln in self.vulnerabilities:
            if vuln.owasp_category:
                if isinstance(vuln.owasp_category, list):
                    for category in vuln.owasp_category:
                        owasp_categories.add(category)
                        standards["OWASP"]["categories"][category] += 1
                else:
                    owasp_categories.add(vuln.owasp_category)
                    standards["OWASP"]["categories"][vuln.owasp_category] += 1

            if vuln.cwe_id:
                if isinstance(vuln.cwe_id, list):
                    for cwe in vuln.cwe_id:
                        cwe_ids.add(cwe)
                        standards["CWE"]["weaknesses"][cwe] += 1
                else:
                    cwe_ids.add(vuln.cwe_id)
                    standards["CWE"]["weaknesses"][vuln.cwe_id] += 1

        standards["OWASP"]["covered"] = len(owasp_categories)
        standards["CWE"]["covered"] = len(cwe_ids)

        # TODO: Add actual totals for complete compliance reporting
        standards["OWASP"]["total"] = 10  # OWASP Top 10
        standards["CWE"]["total"] = 25  # Common CWE Top 25

        return standards

    def _save_report(self, report: Dict[str, Any]):
        """Save vulnerability report to file"""
        try:
            with open(self.output_path, "w") as f:
                json.dump(report, f, indent=2)
            logger.info(f"Report saved to {self.output_path}")
        except Exception as e:
            logger.error(f"Error saving report: {e}")


def main():
    """Main entry point for command-line execution"""
    parser = argparse.ArgumentParser(
        description="Production-Grade Vulnerability Detector",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )

    parser.add_argument(
        "-s",
        "--source-dir",
        default=".",
        help="Directory containing source code to analyze",
    )
    parser.add_argument(
        "-r", "--rules-dir", default="rules", help="Directory containing security rules"
    )
    parser.add_argument(
        "-o",
        "--output",
        default="vulnerability_report.json",
        help="Output file path for the report",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable verbose logging"
    )
    parser.add_argument("--log-file", help="Path to log file (optional)")
    parser.add_argument(
        "-w",
        "--workers",
        type=int,
        default=min(cpu_count(), 8),
        help="Number of parallel workers",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=300,
        help="Timeout in seconds for individual analysis tasks",
    )
    parser.add_argument(
        "--use-semgrep-registry",
        action="store_true",
        help="Use Semgrep Registry rules for real-time scanning if local rules are missing",
    )

    args = parser.parse_args()

    # Setup logging
    setup_logging(verbose=args.verbose, log_file=args.log_file)

    # Create configuration
    config = {
        "source_dir": args.source_dir,
        "rules_dir": args.rules_dir,
        "output_path": args.output,
        "max_workers": args.workers,
        "timeout": args.timeout,
        "use_semgrep_registry": args.use_semgrep_registry,
    }

    try:
        # Initialize and run detector
        detector = VulnerabilityDetector(config)
        report = detector.scan_codebase()

        # Print summary
        print("\nScan Summary:")
        print(f"Files processed: {report['scan_info']['total_files_processed']}")
        print(f"Vulnerabilities found: {report['scan_info']['total_vulnerabilities']}")
        print(
            f"Scan duration: {report['scan_info']['scan_duration_seconds']:.2f} seconds"
        )
        print(f"Report saved to: {args.output}")

        if report["scan_info"]["total_vulnerabilities"] > 0:
            print("\nSeverity Breakdown:")
            for severity, count in report["summary"]["severity_breakdown"].items():
                print(f"  {severity}: {count}")

            print("\nTop Recommendations:")
            for rec in report["recommendations"][:3]:
                print(f"  [{rec['priority']}] {rec['recommendation']}")

        return 0 if report["scan_info"]["total_vulnerabilities"] == 0 else 1

    except Exception as e:
        logger.error(f"Fatal error during execution: {e}")
        return 2


if __name__ == "__main__":
    sys.exit(main())