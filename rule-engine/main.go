package main

import (
	"bytes"
	"crypto/md5"
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"gopkg.in/yaml.v3"
)

// ANSI color codes for logging
const (
	ColorReset  = "\033[0m"
	ColorRed    = "\033[31m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorBlue   = "\033[34m"
	ColorPurple = "\033[35m"
	ColorCyan   = "\033[36m"
)

// Logger levels
const (
	DEBUG = iota
	INFO
	WARNING
	ERROR
	CRITICAL
)

type Logger struct {
	level   int
	verbose bool
}

func NewLogger(verbose bool) *Logger {
	level := INFO
	if verbose {
		level = DEBUG
	}
	return &Logger{level: level, verbose: verbose}
}

func (l *Logger) log(level int, format string, args ...interface{}) {
	if level < l.level {
		return
	}

	levelNames := []string{"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
	colors := []string{ColorCyan, ColorGreen, ColorYellow, ColorRed, ColorPurple}

	timestamp := time.Now().Format("15:04:05")
	levelName := levelNames[level]
	color := colors[level]

	prefix := fmt.Sprintf("%s | %s%s%s | ", timestamp, color, levelName, ColorReset)
	message := fmt.Sprintf(format, args...)
	fmt.Printf("%s%s\n", prefix, message)
}

func (l *Logger) Debug(format string, args ...interface{}) {
	l.log(DEBUG, format, args...)
}

func (l *Logger) Info(format string, args ...interface{}) {
	l.log(INFO, format, args...)
}

func (l *Logger) Warning(format string, args ...interface{}) {
	l.log(WARNING, format, args...)
}

func (l *Logger) Error(format string, args ...interface{}) {
	l.log(ERROR, format, args...)
}

func (l *Logger) Critical(format string, args ...interface{}) {
	l.log(CRITICAL, format, args...)
}

var logger *Logger

// Rule represents a security detection rule
type Rule struct {
	ID            string                 `yaml:"id" json:"id"`
	Category      string                 `yaml:"category" json:"category"`
	Type          string                 `yaml:"type" json:"type"` // 'semgrep', 'regex'
	Pattern       interface{}            `yaml:"pattern,flow" json:"pattern"`
	Severity      string                 `yaml:"severity" json:"severity"`
	Description   string                 `yaml:"message" json:"description"`
	Remediation   string                 `yaml:"fix" json:"remediation"`
	Language      string                 `yaml:"language" json:"language"`
	CWEID         string                 `yaml:"cwe" json:"cwe_id,omitempty"`
	OWASPCategory string                 `yaml:"owasp" json:"owasp_category,omitempty"`
	Confidence    string                 `yaml:"confidence" json:"confidence"`
	Tags          []string               `yaml:"tags" json:"tags"`
	Metadata      map[string]interface{} `yaml:"metadata,omitempty" json:"metadata,omitempty"`
	FilePath      string                 // Path to the rule's YAML file
}

// Normalize severity and set defaults
func (r *Rule) Normalize() {
	r.Severity = strings.ToUpper(r.Severity)
	validSeverities := map[string]bool{
		"CRITICAL": true, "HIGH": true, "MEDIUM": true, "LOW": true, "INFO": true,
	}
	if !validSeverities[r.Severity] {
		r.Severity = "MEDIUM"
	}
	if r.Confidence == "" {
		r.Confidence = "HIGH"
	}
	if r.Tags == nil {
		r.Tags = []string{}
	}
}

// Vulnerability represents a detected security vulnerability
type Vulnerability struct {
	RuleID            string                 `json:"rule_id"`
	Category          string                 `json:"category"`
	Severity          string                 `json:"severity"`
	Location          string                 `json:"location"`
	Details           string                 `json:"details"`
	Remediation       string                 `json:"remediation"`
	Context           map[string]interface{} `json:"context"`
	CWEIDependency    string                 `json:"cwe_id,omitempty"`
	OWASPDependency   string                 `json:"review_guidance,omitempty"`
	Confidence        string                 `json:"confidence"`
	DependencyFile    string                 `json:"dependency_file,omitempty"`
	LineNumber        int                    `json:"line_number"`
	ColumnNumber      int                    `json:"column_number"`
	CodeSnippet       string                 `json:"code_snippet"`
	DependencyVersion string                 `json:"dependency_version,omitempty"`
}

// LanguagePatterns holds language detection patterns
type LanguagePatterns struct {
	Extensions []string          `json:"extensions"`
	Keywords   map[string]bool   `json:"keywords"`
	Imports    map[string]bool   `json:"imports"`
	DataTypes  map[string]bool   `json:"data_types"`
}

// LanguageDetector provides language detection functionality
type LanguageDetector struct {
	patterns map[string]LanguagePatterns
}

func NewLanguageDetector() *LanguageDetector {
	patterns := map[string]LanguagePatterns{
		"java": {
			Extensions: []string{".java"},
			Keywords: map[string]bool{
				"public": true, "private": true, "protected": true, "class": true,
				"interface": true, "package": true, "import": true,
			},
			Imports: map[string]bool{
				"java.": true, "javax.": true, "org.springframework": true,
			},
			DataTypes: map[string]bool{
				"String": true, "Integer": true, "List": true, "Map": true, "Set": true,
			},
		},
		"cpp": {
			Extensions: []string{".cpp", ".cc", ".cxx", ".c++", ".hpp", ".h", ".c"},
			Keywords: map[string]bool{
				"std::": true, "#include": true, "#define": true, "namespace": true, "using": true,
			},
			Imports: map[string]bool{
				"iostream": true, "vector": true, "string": true, "algorithm": true,
			},
			DataTypes: map[string]bool{
				"int": true, "char": true, "double": true, "float": true, "bool": true, "void": true,
			},
		},
		"python": {
			Extensions: []string{".py", ".py3", ".pyw"},
			Keywords: map[string]bool{
				"def": true, "class": true, "import": true, "from": true,
				"__init__": true, "if __name__": true,
			},
			Imports: map[string]bool{
				"os": true, "sys": true, "json": true, "requests": true, "flask": true, "django": true,
			},
			DataTypes: map[string]bool{},
		},
		"javascript": {
			Extensions: []string{".js", ".jsx", ".ts", ".tsx", ".mjs"},
			Keywords: map[string]bool{
				"function": true, "var": true, "let": true, "const": true,
				"class": true, "import": true, "require": true,
			},
			Imports: map[string]bool{
				"require": true, "express": true, "react": true, "lodash": true, "axios": true,
			},
			DataTypes: map[string]bool{
				"string": true, "number": true, "boolean": true, "object": true, "array": true,
			},
		},
		"csharp": {
			Extensions: []string{".cs"},
			Keywords: map[string]bool{
				"using": true, "namespace": true, "class": true, "public": true,
				"private": true, "static": true,
			},
			Imports: map[string]bool{
				"System": true, "Microsoft": true, "Newtonsoft": true,
			},
			DataTypes: map[string]bool{
				"string": true, "int": true, "bool": true, "double": true, "var": true,
			},
		},
	}

	return &LanguageDetector{patterns: patterns}
}

func (ld *LanguageDetector) DetectFromFile(filePath string) string {
	// Check by extension first
	ext := strings.ToLower(filepath.Ext(filePath))
	for lang, patterns := range ld.patterns {
		for _, extension := range patterns.Extensions {
			if ext == extension {
				return lang
			}
		}
	}

	// If extension detection fails, analyze content
	content, err := os.ReadFile(filePath)
	if err != nil {
		logger.Debug("Error reading file %s: %v", filePath, err)
		return "unknown"
	}

	// Read first 1KB for analysis
	if len(content) > 1024 {
		content = content[:1024]
	}

	return ld.analyzeContent(string(content))
}

func (ld *LanguageDetector) analyzeContent(content string) string {
	contentLower := strings.ToLower(content)
	scores := make(map[string]int)

	for lang, patterns := range ld.patterns {
		score := 0
		for keyword := range patterns.Keywords {
			keywordLower := strings.ToLower(keyword)
			score += strings.Count(contentLower, keywordLower)
		}
		scores[lang] = score
	}

	// Find language with highest score
	maxScore := 0
	detectedLang := "unknown"
	for lang, score := range scores {
		if score > maxScore {
			maxScore = score
			detectedLang = lang
		}
	}

	if maxScore > 0 {
		return detectedLang
	}
	return "unknown"
}

func (ld *LanguageDetector) GetFileExtension(language string) string {
	extMap := map[string]string{
		"python":     ".py",
		"java":       ".java",
		"javascript": ".js",
		"cpp":        ".cpp",
		"c":          ".c",
		"csharp":     ".cs",
	}
	if ext, ok := extMap[language]; ok {
		return ext
	}
	return ".txt"
}

// Statistics holds scan statistics
type Statistics struct {
	FilesProcessed      int           `json:"files_processed"`
	RulesLoaded         int           `json:"rules_loaded"`
	VulnerabilitiesFound int          `json:"vulnerabilities_found"`
	ScanStartTime       *time.Time    `json:"scan_start_time"`
	ScanEndTime         *time.Time    `json:"scan_end_time"`
	ScanDuration        time.Duration `json:"scan_duration"`
}

// VulnerabilityDetector is the main detection engine
type VulnerabilityDetector struct {
	config             map[string]interface{}
	rules              map[string][]Rule
	vulnerabilities    []Vulnerability
	sourceDir          string
	outputPath         string
	rulesDir           string
	maxWorkers         int
	timeout            int
	useSemgrepRegistry bool
	languageDetector   *LanguageDetector
	stats              Statistics
	mu                 sync.Mutex
}

func NewVulnerabilityDetector(config map[string]interface{}) *VulnerabilityDetector {
	sourceDir := getStringConfig(config, "source_dir", ".")
	rulesDir := getStringConfig(config, "rules_dir", "rules")
	outputPath := getStringConfig(config, "output_path", "vulnerability_report.json")
	maxWorkers := getIntConfig(config, "max_workers", min(runtime.NumCPU()*2, 16)) // Increased default for better concurrency
	timeout := getIntConfig(config, "timeout", 300)
	useSemgrepRegistry := getBoolConfig(config, "use_semgrep_registry", false)

	detector := &VulnerabilityDetector{
		config:             config,
		rules:              make(map[string][]Rule),
		vulnerabilities:    []Vulnerability{},
		sourceDir:          sourceDir,
		outputPath:         outputPath,
		rulesDir:           rulesDir,
		maxWorkers:         maxWorkers,
		timeout:            timeout,
		useSemgrepRegistry: useSemgrepRegistry,
		languageDetector:   NewLanguageDetector(),
		stats:              Statistics{},
	}

	// Create default rules if rules directory doesn't exist
	if _, err := os.Stat(rulesDir); os.IsNotExist(err) {
		detector.createDefaultRules()
	}

	logger.Info("Initialized VulnerabilityDetector with %d workers", maxWorkers)
	return detector
}

func (vd *VulnerabilityDetector) createDefaultRules() {
	err := os.MkdirAll(vd.rulesDir, 0755)
	if err != nil {
		logger.Error("Failed to create rules directory: %v", err)
		return
	}

	defaultRules := map[string][]map[string]interface{}{
		"python": {
			{
				"id":          "py-sql-injection",
				"category":    "Security",
				"type":        "regex",
				"pattern":     `(execute|cursor\.execute|query)\s*\(\s*["'].*%.*["']`,
				"severity":    "HIGH",
				"message":     "Potential SQL injection vulnerability",
				"fix":         "Use parameterized queries",
				"cwe":         "CWE-89",
				"owasp":       "A03:2021",
			},
			{
				"id":          "py-command-injection",
				"category":    "Security",
				"type":        "regex",
				"pattern":     `(os\.system|subprocess\.call|subprocess\.run|os\.popen)\s*\([^)]*\+`,
				"severity":    "HIGH",
				"message":     "Potential command injection vulnerability",
				"fix":         "Use subprocess with shell=False and validate inputs",
				"cwe":         "CWE-78",
				"owasp":       "A03:2021",
			},
		},
		"java": {
			{
				"id":          "java-sql-injection",
				"category":    "Security",
				"type":        "regex",
				"pattern":     `(executeQuery|executeUpdate|execute)\s*\(\s*["'].*\+`,
				"severity":    "HIGH",
				"message":     "Potential SQL injection vulnerability",
				"fix":         "Use PreparedStatement with parameter binding",
				"cwe":         "CWE-89",
				"owasp":       "A03:2021",
			},
			{
				"id":          "java-println",
				"category":    "Security",
				"type":        "semgrep",
				"pattern":     "System.out.println(...)",
				"severity":    "LOW",
				"message":     "Avoid using System.out.println in production code",
				"fix":         "Use a logging framework like SLF4J",
				"cwe":         "CWE-532",
				"owasp":       "A09:2021",
			},
		},
		"javascript": {
			{
				"id":          "js-xss",
				"category":    "Security",
				"type":        "regex",
				"pattern":     `(innerHTML|outerHTML|document\.write)\s*=.*\+`,
				"severity":    "MEDIUM",
				"message":     "Potential XSS vulnerability",
				"fix":         "Sanitize user input before DOM insertion",
				"cwe":         "CWE-79",
				"owasp":       "A03:2021",
			},
		},
	}

	for lang, rules := range defaultRules {
		langDir := filepath.Join(vd.rulesDir, lang)
		err := os.MkdirAll(langDir, 0755)
		if err != nil {
			logger.Error("Failed to create language directory %s: %v", langDir, err)
			continue
		}

		rulesFile := filepath.Join(langDir, "default.yaml")
		data := map[string]interface{}{"rules": rules}

		yamlData, err := yaml.Marshal(data)
		if err != nil {
			logger.Error("Failed to marshal rules for %s: %v", lang, err)
			continue
		}

		err = os.WriteFile(rulesFile, yamlData, 0644)
		if err != nil {
			logger.Error("Failed to write rules file %s: %v", rulesFile, err)
			continue
		}
	}

	logger.Info("Created default rules in %s", vd.rulesDir)
}

func (vd *VulnerabilityDetector) ScanCodebase() (map[string]interface{}, error) {
	startTime := time.Now()
	vd.stats.ScanStartTime = &startTime
	logger.Info("Starting vulnerability scan of %s", vd.sourceDir)

	// Discover files concurrently
	sourceFiles, err := vd.discoverSourceFiles()
	if err != nil {
		return nil, fmt.Errorf("failed to discover source files: %w", err)
	}

	if len(sourceFiles) == 0 {
		logger.Warning("No source files found to scan")
		return vd.generateReport(), nil
	}

	logger.Info("Found %d source files", len(sourceFiles))

	// Process files in parallel
	jobs := make(chan string, len(sourceFiles))
	results := make(chan []Vulnerability, len(sourceFiles))

	// Start workers
	var wg sync.WaitGroup
	for i := 0; i < vd.maxWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for filePath := range jobs {
				vulns := vd.processFile(filePath)
				results <- vulns
			}
		}()
	}

	// Send jobs
	go func() {
		defer close(jobs)
		for _, filePath := range sourceFiles {
			jobs <- filePath
		}
	}()

	// Collect results
	go func() {
		wg.Wait()
		close(results)
	}()

	for vulns := range results {
		vd.mu.Lock()
		vd.vulnerabilities = append(vd.vulnerabilities, vulns...)
		vd.stats.FilesProcessed++
		vd.mu.Unlock()

		if len(vulns) > 0 {
			logger.Info("Found %d vulnerabilities in file", len(vulns))
		}
	}

	endTime := time.Now()
	vd.stats.ScanEndTime = &endTime
	vd.stats.ScanDuration = endTime.Sub(startTime)
	vd.stats.VulnerabilitiesFound = len(vd.vulnerabilities)

	// Generate and save report
	report := vd.generateReport()
	vd.saveReport(report)

	return report, nil
}

func (vd *VulnerabilityDetector) discoverSourceFiles() ([]string, error) {
    var sourceFiles []string
    var mu sync.Mutex // Thread-safe append to sourceFiles

    // Get all supported extensions
    allExtensions := make(map[string]bool)
    for _, patterns := range vd.languageDetector.patterns {
        for _, ext := range patterns.Extensions {
            allExtensions[ext] = true
        }
    }

    // Skip common non-source directories
    skipDirs := map[string]bool{
        "node_modules": true, "__pycache__": true, "venv": true, "env": true,
        "build": true, "dist": true, "target": true, ".git": true, ".svn": true,
        ".hg": true, "vendor": true,
    }

    // Check if sourceDir is a file
    fileInfo, err := os.Stat(vd.sourceDir)
    if err != nil {
        return nil, fmt.Errorf("failed to stat source path %s: %w", vd.sourceDir, err)
    }

    if !fileInfo.IsDir() {
        // Single file input
        ext := strings.ToLower(filepath.Ext(vd.sourceDir))
        if allExtensions[ext] {
            sourceFiles = append(sourceFiles, vd.sourceDir)
            logger.Debug("Single file input detected: %s", vd.sourceDir)
            return sourceFiles, nil
        }
        return nil, fmt.Errorf("single file %s has unsupported extension", vd.sourceDir)
    }

    // Directory input: proceed with concurrent traversal
    var initialDirs []string
    var initialFiles []string
    dirEntries, err := os.ReadDir(vd.sourceDir)
    if err != nil {
        return nil, fmt.Errorf("failed to read directory %s: %w", vd.sourceDir, err)
    }

    for _, entry := range dirEntries {
        path := filepath.Join(vd.sourceDir, entry.Name())
        if entry.IsDir() {
            if !strings.HasPrefix(entry.Name(), ".") && !skipDirs[entry.Name()] {
                initialDirs = append(initialDirs, path)
            }
        } else if ext := strings.ToLower(filepath.Ext(path)); allExtensions[ext] {
            initialFiles = append(initialFiles, path)
        }
    }

    // Add initial files
    mu.Lock()
    sourceFiles = append(sourceFiles, initialFiles...)
    mu.Unlock()

    // Process directories concurrently
    dirJobs := make(chan string, len(initialDirs))
    fileResults := make(chan []string, len(initialDirs))

    // Start workers for directory traversal
    var wg sync.WaitGroup
    numWorkers := min(vd.maxWorkers, len(initialDirs)+1)
    for i := 0; i < numWorkers; i++ {
        wg.Add(1)
        go func() {
            defer wg.Done()
            for dirPath := range dirJobs {
                var localFiles []string
                err := filepath.WalkDir(dirPath, func(path string, d fs.DirEntry, err error) error {
                    if err != nil {
                        return err
                    }
                    if d.IsDir() {
                        dirName := d.Name()
                        if strings.HasPrefix(dirName, ".") || skipDirs[dirName] {
                            return filepath.SkipDir
                        }
                        return nil
                    }
                    if ext := strings.ToLower(filepath.Ext(path)); allExtensions[ext] {
                        localFiles = append(localFiles, path)
                    }
                    return nil
                })
                if err != nil {
                    logger.Error("Error walking directory %s: %v", dirPath, err)
                }
                fileResults <- localFiles
            }
        }()
    }

    // Send directory jobs
    go func() {
        defer close(dirJobs)
        for _, dirPath := range initialDirs {
            dirJobs <- dirPath
        }
    }()

    // Collect file results
    go func() {
        wg.Wait()
        close(fileResults)
    }()

    // Aggregate files
    for files := range fileResults {
        mu.Lock()
        sourceFiles = append(sourceFiles, files...)
        mu.Unlock()
    }

    return sourceFiles, nil
}

func (vd *VulnerabilityDetector) processFile(filePath string) []Vulnerability {
	var vulnerabilities []Vulnerability
	var mu sync.Mutex // Thread-safe vulnerability collection

	// Detect language
	language := vd.languageDetector.DetectFromFile(filePath)
	if language == "unknown" {
		logger.Debug("Unknown language for file: %s", filePath)
		return vulnerabilities
	}

	// Read file content
	content, err := os.ReadFile(filePath)
	if err != nil {
		logger.Error("Error reading file %s: %v", filePath, err)
		return vulnerabilities
	}

	// Load local rules for this language
	rules := vd.loadRules(language)
	if len(rules) > 0 {
		logger.Info("Applying %d local rules for %s to %s", len(rules), language, filePath)

		// Create channels for rule processing
		ruleJobs := make(chan Rule, len(rules))
		ruleResults := make(chan []Vulnerability, len(rules))

		// Start worker pool for rule application
		var wg sync.WaitGroup
		numRuleWorkers := min(vd.maxWorkers, len(rules))
		for i := 0; i < numRuleWorkers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for rule := range ruleJobs {
					ruleVulns := vd.applyRule(rule, string(content), filePath, language)
					ruleResults <- ruleVulns
				}
			}()
		}

		// Send rules to workers
		go func() {
			defer close(ruleJobs)
			for _, rule := range rules {
				ruleJobs <- rule
			}
		}()

		// Collect rule results
		go func() {
			wg.Wait()
			close(ruleResults)
		}()

		// Aggregate vulnerabilities
		for ruleVulns := range ruleResults {
			mu.Lock()
			vulnerabilities = append(vulnerabilities, ruleVulns...)
			mu.Unlock()
		}
	} else {
		logger.Debug("No local rules found for language: %s", language)
	}

	// Perform real-time Semgrep scan if enabled
	if vd.useSemgrepRegistry {
		logger.Info("Performing real-time Semgrep scan for %s on %s", language, filePath)
		semgrepVulns := vd.realtimeSemgrepScan(language, string(content), filePath)
		mu.Lock()
		vulnerabilities = append(vulnerabilities, semgrepVulns...)
		mu.Unlock()
	}

	return vulnerabilities
}

func (vd *VulnerabilityDetector) loadRules(language string) []Rule {
	vd.mu.Lock()
	if rules, exists := vd.rules[language]; exists {
		vd.mu.Unlock()
		return rules
	}
	vd.mu.Unlock()

	var rules []Rule
	var mu sync.Mutex
	langRulesDir := filepath.Join(vd.rulesDir, language)

	if _, err := os.Stat(langRulesDir); os.IsNotExist(err) {
		logger.Debug("No rules directory for language: %s", language)
		return rules
	}

	// Collect YAML file paths
	var ruleFiles []string
	err := filepath.WalkDir(langRulesDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && (strings.HasSuffix(strings.ToLower(path), ".yaml") || strings.HasSuffix(strings.ToLower(path), ".yml")) {
			ruleFiles = append(ruleFiles, path)
		}
		return nil
	})
	if err != nil {
		logger.Error("Error walking rules directory %s: %v", langRulesDir, err)
		return rules
	}

	// Create channels for rule loading
	fileJobs := make(chan string, len(ruleFiles))
	ruleResults := make(chan []Rule, len(ruleFiles))

	// Start worker pool for rule loading
	var wg sync.WaitGroup
	numWorkers := min(vd.maxWorkers, len(ruleFiles))
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for path := range fileJobs {
				fileRules, err := vd.loadRulesFromFile(path, language)
				if err != nil {
					logger.Error("Error loading rule file %s: %v", path, err)
					ruleResults <- []Rule{}
					continue
				}
				for i := range fileRules {
					fileRules[i].FilePath = path
				}
				ruleResults <- fileRules
			}
		}()
	}

	// Send file paths to workers
	go func() {
		defer close(fileJobs)
		for _, path := range ruleFiles {
			fileJobs <- path
		}
	}()

	// Collect rule results
	go func() {
		wg.Wait()
		close(ruleResults)
	}()

	// Aggregate rules
	for fileRules := range ruleResults {
		mu.Lock()
		rules = append(rules, fileRules...)
		mu.Unlock()
	}

	vd.mu.Lock()
	vd.rules[language] = rules
	vd.stats.RulesLoaded += len(rules)
	vd.mu.Unlock()

	return rules
}

func (vd *VulnerabilityDetector) loadRulesFromFile(filePath, language string) ([]Rule, error) {
	var rules []Rule

	data, err := os.ReadFile(filePath)
	if err != nil {
		return rules, err
	}

	var ruleData struct {
		Rules []map[string]interface{} `yaml:"rules"`
	}

	err = yaml.Unmarshal(data, &ruleData)
	if err != nil {
		return rules, err
	}

	for _, ruleDict := range ruleData.Rules {
		rule := vd.createRuleFromDict(ruleDict, language)
		if rule != nil {
			rules = append(rules, *rule)
		}
	}

	return rules, nil
}

func (vd *VulnerabilityDetector) createRuleFromDict(ruleDict map[string]interface{}, language string) *Rule {
	rule := &Rule{
		ID:            getStringFromMap(ruleDict, "id", "unknown"),
		Category:      getStringFromMap(ruleDict, "category", "Security"),
		Type:          getStringFromMap(ruleDict, "type", "semgrep"),
		Pattern:       ruleDict["pattern"],
		Severity:      getStringFromMap(ruleDict, "severity", "MEDIUM"),
		Description:   getStringFromMap(ruleDict, "message", "No description"),
		Remediation:   getStringFromMap(ruleDict, "fix", "No remediation provided"),
		Language:      language,
		CWEID:         getStringFromMap(ruleDict, "cwe", ""),
		OWASPCategory: getStringFromMap(ruleDict, "owasp", ""),
		Confidence:    getStringFromMap(ruleDict, "confidence", "HIGH"),
	}

	if tags, ok := ruleDict["tags"].([]interface{}); ok {
		for _, tag := range tags {
			if tagStr, ok := tag.(string); ok {
				rule.Tags = append(rule.Tags, tagStr)
			}
		}
	}

	if metadata, ok := ruleDict["metadata"].(map[string]interface{}); ok {
		rule.Metadata = metadata
	}

	rule.Normalize()
	return rule
}

func (vd *VulnerabilityDetector) applyRule(rule Rule, content, filePath, language string) []Vulnerability {
	switch rule.Type {
	case "regex":
		return vd.applyRegexRule(rule, content, filePath)
	case "semgrep":
		return vd.applySemgrepRule(rule, content, filePath, language)
	default:
		logger.Debug("Unknown rule type %s for rule %s", rule.Type, rule.ID)
		return []Vulnerability{}
	}
}

func (vd *VulnerabilityDetector) applyRegexRule(rule Rule, content, filePath string) []Vulnerability {
	var vulnerabilities []Vulnerability

	var pattern string
	switch p := rule.Pattern.(type) {
	case string:
		pattern = p
	case map[string]interface{}:
		if patternStr, ok := p["pattern"].(string); ok {
			pattern = patternStr
		}
	default:
		logger.Error("Invalid pattern type in rule %s", rule.ID)
		return vulnerabilities
	}

	if pattern == "" {
		return vulnerabilities
	}

	regex, err := regexp.Compile(pattern)
	if err != nil {
		logger.Error("Invalid regex pattern in rule %s: %v", rule.ID, err)
		return vulnerabilities
	}

	lines := strings.Split(content, "\n")
	for lineNum, line := range lines {
		matches := regex.FindAllStringIndex(line, -1)
		for _, match := range matches {
			location := fmt.Sprintf("%s:%d:%d", filepath.Base(filePath), lineNum+1, match[0]+1)
			codeSnippet := strings.TrimSpace(line)

			hash := md5.Sum([]byte(fmt.Sprintf("%s:%s", rule.ID, location)))

			vulnerability := Vulnerability{
				RuleID:            rule.ID,
				Category:          rule.Category,
				Severity:          rule.Severity,
				Location:          location,
				Details:           rule.Description,
				Remediation:       rule.Remediation,
				Context: map[string]interface{}{
					"file_path": filePath,
					"match":     line[match[0]:match[1]],
					"line":      strings.TrimSpace(line),
				},
				CWEIDependency:    rule.CWEID,
				OWASPDependency:   rule.OWASPCategory,
				Confidence:        rule.Confidence,
				DependencyFile:    fmt.Sprintf("%x", hash),
				LineNumber:        lineNum + 1,
				ColumnNumber:      match[0] + 1,
				CodeSnippet:       codeSnippet,
				DependencyVersion: "",
			}

			vulnerabilities = append(vulnerabilities, vulnerability)
		}
	}

	return vulnerabilities
}

func (vd *VulnerabilityDetector) applySemgrepRule(rule Rule, content, filePath, language string) []Vulnerability {
	// Create temporary directory
	tmpDir, err := os.MkdirTemp("", "semgrep_scan_*")
	if err != nil {
		logger.Error("Failed to create temp directory: %v", err)
		return []Vulnerability{}
	}
	defer os.RemoveAll(tmpDir)

	// Create source file
	ext := vd.languageDetector.GetFileExtension(language)
	sourceFile := filepath.Join(tmpDir, "source"+ext)
	err = os.WriteFile(sourceFile, []byte(content), 0644)
	if err != nil {
		logger.Error("Failed to create temp source file: %v", err)
		return []Vulnerability{}
	}

	// Log source file content for debugging
	sourceContent, _ := os.ReadFile(sourceFile)
	logger.Debug("Source file content for %s:\n%s", sourceFile, string(sourceContent))

	// Use the rule's original YAML file
	if rule.FilePath == "" {
		logger.Error("No file path specified for rule %s", rule.ID)
		return []Vulnerability{}
	}

	// Validate rule file exists
	if _, err := os.Stat(rule.FilePath); os.IsNotExist(err) {
		logger.Error("Rule file %s does not exist for rule %s", rule.FilePath, rule.ID)
		return []Vulnerability{}
	}

	// Log rule file content for debugging
	ruleContent, _ := os.ReadFile(rule.FilePath)
	logger.Debug("Applying Semgrep rule %s from %s", rule.ID, rule.FilePath)
	logger.Debug("Rule file content for %s:\n%s", rule.FilePath, string(ruleContent))

	// Execute Semgrep
	return vd.executeSemgrep(rule.FilePath, sourceFile, filePath, language)
}

func (vd *VulnerabilityDetector) executeSemgrep(rulesFile, sourceFile, originalFile, language string) []Vulnerability {
	var vulnerabilities []Vulnerability

	args := []string{
		"semgrep",
		"--config", rulesFile,
		"--json",
		"--quiet",
		"--timeout", strconv.Itoa(vd.timeout),
		sourceFile,
	}
	cmd := exec.Command(args[0], args[1:]...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	logger.Debug("Executing Semgrep command: %s", strings.Join(args, " "))

	err := cmd.Run()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			logger.Error("Semgrep failed for rule file %s with exit code %d: %s", rulesFile, exitErr.ExitCode(), stderr.String())
			logger.Debug("Semgrep stdout: %s", stdout.String())
		} else {
			logger.Error("Semgrep failed for rule file %s: %v, stderr: %s, stdout: %s", rulesFile, err, stderr.String(), stdout.String())
		}
		return vulnerabilities
	}

	var semgrepOutput struct {
		Results []struct {
			RuleID    string `json:"check_id"`
			Message   string `json:"message"`
			Path      string `json:"path"`
			Start     struct {
				Line int `json:"line"`
				Col  int `json:"col"`
			} `json:"start"`
			End struct {
				Line int `json:"line"`
				Col  int `json:"col"`
			} `json:"end"`
			Severity string `json:"severity"`
			Extra    struct {
				Message   string                 `json:"message"`
				Metadata  map[string]interface{} `json:"metadata"`
				Severity  string                 `json:"severity"`
				Lines     string                 `json:"lines"`
			} `json:"extra"`
		} `json:"results"`
	}

	err = json.Unmarshal(stdout.Bytes(), &semgrepOutput)
	if err != nil {
		logger.Error("Failed to parse Semgrep JSON output for rule file %s: %v, stdout: %s", rulesFile, err, stdout.String())
		return vulnerabilities
	}

	for _, result := range semgrepOutput.Results {
		location := fmt.Sprintf("%s:%d:%d", filepath.Base(originalFile), result.Start.Line, result.Start.Col)
		hash := md5.Sum([]byte(fmt.Sprintf("%s:%s", result.RuleID, location)))

		cweid := ""
		owasp := ""
		confidence := "HIGH"

		if result.Extra.Metadata != nil {
			if cwe, ok := result.Extra.Metadata["cwe"].(string); ok {
				cweid = cwe
			} else if cweSlice, ok := result.Extra.Metadata["cwe"].([]interface{}); ok && len(cweSlice) > 0 {
				if cweStr, ok := cweSlice[0].(string); ok {
					cweid = cweStr
				}
			}
			if owaspVal, ok := result.Extra.Metadata["owasp"].(string); ok {
				owasp = owaspVal
			}
			if conf, ok := result.Extra.Metadata["confidence"].(string); ok {
				confidence = conf
			}
		}

		severity := result.Severity
		if severity == "" {
			severity = result.Extra.Severity
		}
		switch strings.ToUpper(severity) {
		case "ERROR":
			severity = "HIGH"
		case "WARNING":
			severity = "MEDIUM"
		case "INFO":
			severity = "LOW"
		default:
			severity = "MEDIUM"
		}

		details := result.Message
		if details == "" {
			details = result.Extra.Message
		}
		if details == "" {
			details = "Vulnerability detected by Semgrep"
		}

		codeSnippet := strings.TrimSpace(result.Extra.Lines)
		if codeSnippet == "" {
			codeSnippet = "Content unavailable"
		}

		vulnerability := Vulnerability{
			RuleID:            result.RuleID,
			Category:          "Security",
			Severity:          severity,
			Location:          location,
			Details:           details,
			Remediation:       "Follow Semgrep recommendations",
			Context: map[string]interface{}{
				"file_path": originalFile,
				"lines":     result.Extra.Lines,
				"semgrep":   true,
			},
			CWEIDependency:    cweid,
			OWASPDependency:   owasp,
			Confidence:        confidence,
			DependencyFile:    fmt.Sprintf("%x", hash),
			LineNumber:        result.Start.Line,
			ColumnNumber:      result.Start.Col,
			CodeSnippet:       codeSnippet,
			DependencyVersion: "",
		}

		vulnerabilities = append(vulnerabilities, vulnerability)
	}

	return vulnerabilities
}

func (vd *VulnerabilityDetector) realtimeSemgrepScan(language, content, filePath string) []Vulnerability {
	var vulnerabilities []Vulnerability
	var mu sync.Mutex

	if !vd.useSemgrepRegistry {
		logger.Debug("Semgrep registry scan skipped for %s", language)
		return vulnerabilities
	}

	// Create temporary directory
	tmpDir, err := os.MkdirTemp("", "semgrep_registry_*")
	if err != nil {
		logger.Error("Failed to create temp directory: %v", err)
		return vulnerabilities
	}
	defer os.RemoveAll(tmpDir)

	// Create source file
	ext := vd.languageDetector.GetFileExtension(language)
	sourceFile := filepath.Join(tmpDir, "source"+ext)
	err = os.WriteFile(sourceFile, []byte(content), 0644)
	if err != nil {
		logger.Error("Failed to create temp source file: %v", err)
		return vulnerabilities
	}

	// Log source file content
	sourceContent, _ := os.ReadFile(sourceFile)
	logger.Debug("Source file content for %s:\n%s", sourceFile, string(sourceContent))

	// Define rulesets
	var rulesets []string
	switch language {
	case "python":
		rulesets = []string{"p/security-audit", "p/python"}
	case "java":
		rulesets = []string{"p/security-audit", "p/java"}
	case "javascript":
		rulesets = []string{"p/security-audit", "p/javascript"}
	case "cpp", "c":
		rulesets = []string{"p/security-audit", "p/cpp"}
	case "csharp":
		rulesets = []string{"p/security-audit", "p/csharp"}
	default:
		rulesets = []string{"p/security-audit"}
	}

	// Create channels for ruleset processing
	rulesetJobs := make(chan string, len(rulesets))
	rulesetResults := make(chan []Vulnerability, len(rulesets))

	// Start worker pool for Semgrep scans
	var wg sync.WaitGroup
	numRuleWorkers := min(vd.maxWorkers, len(rulesets))
	for i := 0; i < numRuleWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ruleset := range rulesetJobs {
				args := []string{
					"semgrep",
					"--config", ruleset,
					"--json",
					"--quiet",
					"--timeout", strconv.Itoa(vd.timeout),
					sourceFile,
				}
				cmd := exec.Command(args[0], args[1:]...)

				var stdout, stderr bytes.Buffer
				cmd.Stdout = &stdout
				cmd.Stderr = &stderr

				logger.Debug("Executing Semgrep registry command: %s", strings.Join(args, " "))

				err := cmd.Run()
				if err != nil {
					logger.Debug("Semgrep registry scan failed for %s: %v, stderr: %s", ruleset, err, stderr.String())
					rulesetResults <- []Vulnerability{}
					continue
				}

				var semgrepOutput struct {
					Results []struct {
						RuleID    string `json:"check_id"`
						Message   string `json:"message"`
						Path      string `json:"path"`
						Start     struct {
							Line int `json:"line"`
							Col  int `json:"col"`
						} `json:"start"`
						End struct {
							Line int `json:"line"`
							Col  int `json:"col"`
						} `json:"end"`
						Severity string `json:"severity"`
						Extra    struct {
							Message   string                 `json:"message"`
							Metadata  map[string]interface{} `json:"metadata"`
							Severity  string                 `json:"severity"`
							Lines     string                 `json:"lines"`
						} `json:"extra"`
					} `json:"results"`
				}

				err = json.Unmarshal(stdout.Bytes(), &semgrepOutput)
				if err != nil {
					logger.Error("Failed to parse Semgrep registry output for %s: %v, stdout: %s", ruleset, err, stdout.String())
					rulesetResults <- []Vulnerability{}
					continue
				}

				var ruleVulns []Vulnerability
				for _, result := range semgrepOutput.Results {
					location := fmt.Sprintf("%s:%d:%d", filepath.Base(filePath), result.Start.Line, result.Start.Col)
					hash := md5.Sum([]byte(fmt.Sprintf("%s:%s", result.RuleID, location)))

					cweid := ""
					owasp := ""
					confidence := "HIGH"

					if result.Extra.Metadata != nil {
						if cwe, ok := result.Extra.Metadata["cwe"].(string); ok {
							cweid = cwe
						} else if cweSlice, ok := result.Extra.Metadata["cwe"].([]interface{}); ok && len(cweSlice) > 0 {
							if cweStr, ok := cweSlice[0].(string); ok {
								cweid = cweStr
							}
						}
						if owaspVal, ok := result.Extra.Metadata["owasp"].(string); ok {
							owasp = owaspVal
						}
						if conf, ok := result.Extra.Metadata["confidence"].(string); ok {
							confidence = conf
						}
					}

					severity := result.Severity
					if severity == "" {
						severity = result.Extra.Severity
					}
					switch strings.ToUpper(severity) {
					case "ERROR":
						severity = "HIGH"
					case "WARNING":
						severity = "MEDIUM"
					case "INFO":
						severity = "LOW"
					default:
						severity = "MEDIUM"
					}

					details := result.Message
					if details == "" {
						details = result.Extra.Message
					}
					if details == "" {
						details = "Vulnerability detected by Semgrep"
					}

					codeSnippet := strings.TrimSpace(result.Extra.Lines)
					if codeSnippet == "" {
						codeSnippet = "Content unavailable"
					}

					vulnerability := Vulnerability{
						RuleID:            result.RuleID,
						Category:          "Security",
						Severity:          severity,
						Location:          location,
						Details:           details,
						Remediation:       "Follow Semgrep recommendations",
						Context: map[string]interface{}{
							"file_path": filePath,
							"lines":     result.Extra.Lines,
							"semgrep":   true,
							"registry":  ruleset,
						},
						CWEIDependency:    cweid,
						OWASPDependency:   owasp,
						Confidence:        confidence,
						DependencyFile:    fmt.Sprintf("%x", hash),
						LineNumber:        result.Start.Line,
						ColumnNumber:      result.Start.Col,
						CodeSnippet:       codeSnippet,
						DependencyVersion: "",
					}

					ruleVulns = append(ruleVulns, vulnerability)
				}
				rulesetResults <- ruleVulns
			}
		}()
	}

	// Send rulesets to workers
	go func() {
		defer close(rulesetJobs)
		for _, ruleset := range rulesets {
			rulesetJobs <- ruleset
		}
	}()

	// Collect ruleset results
	go func() {
		wg.Wait()
		close(rulesetResults)
	}()

	// Aggregate vulnerabilities
	for ruleVulns := range rulesetResults {
		mu.Lock()
		vulnerabilities = append(vulnerabilities, ruleVulns...)
		mu.Unlock()
	}

	return vulnerabilities
}

func (vd *VulnerabilityDetector) generateReport() map[string]interface{} {
	severityOrder := map[string]int{
		"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4,
	}

	vd.mu.Lock()
	sort.Slice(vd.vulnerabilities, func(i, j int) bool {
		return severityOrder[vd.vulnerabilities[i].Severity] < severityOrder[vd.vulnerabilities[j].Severity]
	})
	vulnerabilities := make([]Vulnerability, len(vd.vulnerabilities))
	copy(vulnerabilities, vd.vulnerabilities)
	vd.mu.Unlock()

	severityCounts := make(map[string]int)
	categoryCounts := make(map[string]int)
	for _, vuln := range vulnerabilities {
		severityCounts[vuln.Severity]++
		categoryCounts[vuln.Category]++
	}

	report := map[string]interface{}{
		"scan_id": getStringConfig(vd.config, "scan_id", uuid.New().String()),
		"timestamp":        time.Now().Format(time.RFC3339),
		"source_directory": vd.sourceDir,
		"statistics": map[string]interface{}{
			"files_processed":      vd.stats.FilesProcessed,
			"rules_loaded":         vd.stats.RulesLoaded,
			"vulnerabilities_found": vd.stats.VulnerabilitiesFound,
			"scan_start_time":      vd.stats.ScanStartTime.Format(time.RFC3339Nano),
			"scan_end_time":        vd.stats.ScanEndTime.Format(time.RFC3339Nano),
			"scan_duration":        int64(vd.stats.ScanDuration),
		},
		"summary": map[string]interface{}{
			"total_vulnerabilities": len(vulnerabilities),
			"severity_breakdown":    severityCounts,
			"category_breakdown":    categoryCounts,
		},
		"vulnerabilities": vulnerabilities,
		"metadata": map[string]interface{}{
			"tool_version": "1.0.0",
			"rules_used":   vd.stats.RulesLoaded,
			"scan_config": map[string]interface{}{
				"max_workers":          vd.maxWorkers,
				"timeout":              vd.timeout,
				"use_semgrep_registry": vd.useSemgrepRegistry,
			},
		},
	}

	return report
}

func (vd *VulnerabilityDetector) saveReport(report map[string]interface{}) {
	outputDir := filepath.Dir(vd.outputPath)
	if outputDir != "." {
		err := os.MkdirAll(outputDir, 0755)
		if err != nil {
			logger.Error("Failed to create output directory: %v", err)
			return
		}
	}

	jsonData, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		logger.Error("Failed to marshal report: %v", err)
		return
	}

	err = os.WriteFile(vd.outputPath, jsonData, 0644)
	if err != nil {
		logger.Error("Failed to save report: %v", err)
		return
	}

	logger.Info("Report saved to %s", vd.outputPath)

	summaryPath := strings.TrimSuffix(vd.outputPath, filepath.Ext(vd.outputPath)) + "_summary.txt"
	vd.saveReportSummary(report, summaryPath)
}

func (vd *VulnerabilityDetector) saveReportSummary(report map[string]interface{}, summaryPath string) {
	var summary strings.Builder
	summary.WriteString("=== VULNERABILITY SCAN SUMMARY ===\n\n")

	if timestamp, ok := report["timestamp"].(string); ok {
		summary.WriteString(fmt.Sprintf("Scan Timestamp: %s\n", timestamp))
	}

	if sourceDir, ok := report["source_directory"].(string); ok {
		summary.WriteString(fmt.Sprintf("Source Directory: %s", sourceDir))
	}

	summary.WriteString("\n")

	if summaryData, ok := report["summary"].(map[string]interface{}); ok {
		if total, ok := summaryData["total_vulnerabilities"].(int); ok {
			summary.WriteString(fmt.Sprintf("Total Vulnerabilities: %d\n\n", total))
		}

		if severityBreakdown, ok := summaryData["severity"].(map[string]int); ok {
			summary.WriteString("Severity Breakdown:\n")
			severities := []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
			for _, severity := range severities {
				if count, exists := severityBreakdown[severity]; exists && count > 0 {
					summary.WriteString(fmt.Sprintf("  %s: %d\n", severity, count))
				}
			}
			summary.WriteString("\n")
		}
	}

	summary.WriteString("=== DETAILED FINDINGS ===\n\n")

	if vulnerabilities, ok := report["vulnerabilities"].([]Vulnerability); ok {
		for i, vuln := range vulnerabilities {
			summary.WriteString(fmt.Sprintf("%d. [%s] %s\n", i+1, vuln.Severity, vuln.RuleID))
			summary.WriteString(fmt.Sprintf("   Location: %s\n", vuln.Location))
			summary.WriteString(fmt.Sprintf("   Details: %s\n", vuln.Details))
			if vuln.CWEIDependency != "" {
				summary.WriteString(fmt.Sprintf("   CWE: %s\n", vuln.CWEIDependency))
			}
			if vuln.OWASPDependency != "" {
				summary.WriteString(fmt.Sprintf("   OWASP: %s\n", vuln.OWASPDependency))
			}
			summary.WriteString(fmt.Sprintf("   Remediation: %s\n", vuln.Remediation))
			summary.WriteString("\n")
		}
	}

	err := os.WriteFile(summaryPath, []byte(summary.String()), 0644)
	if err != nil {
		logger.Error("Failed to save summary report: %v", err.Error())
	} else {
		logger.Info("Summary report saved to %s", summaryPath)
	}
}

// Utility functions
func getStringConfig(config map[string]interface{}, key, defaultValue string) string {
	if value, ok := config[key].(string); ok {
		return value
	}
	return defaultValue
}

func getIntConfig(config map[string]interface{}, key string, defaultValue int) int {
	if value, ok := config[key].(int); ok {
		return value
	}
	if value, ok := config[key].(float64); ok {
		return int(value)
	}
	return defaultValue
}

func getBoolConfig(config map[string]interface{}, key string, defaultValue bool) bool {
	if value, ok := config[key].(bool); ok {
		return value
	}
	return defaultValue
}

func getStringFromMap(m map[string]interface{}, key, defaultValue string) string {
	if value, ok := m[key].(string); ok {
		return value
	}
	return defaultValue
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Main function and CLI
func main() {
	var (
		sourceDir          = flag.String("source", ".", "Source code directory to scan")
		rulesDir           = flag.String("rules", "rules", "Rules directory")
		outputPath         = flag.String("output", "vulnerability_report.json", "Output file path")
		maxWorkers         = flag.Int("workers", min(runtime.NumCPU()*2, 16), "Maximum number of worker goroutines")
		timeout            = flag.Int("timeout", 300, "Timeout for individual scans in seconds")
		useSemgrepRegistry = flag.Bool("semgrep-registry", false, "Use Semgrep registry rules")
		verbose            = flag.Bool("verbose", true, "Enable verbose logging")
		configFile         = flag.String("config", "", "Configuration file path")
		scanId             = flag.String("scan_id", uuid.New().String(), "Unique identifier for the scan") // Added scan_id flag
	)
	flag.Parse()

	// Initialize logger
	logger = NewLogger(*verbose)

	logger.Info("=== Starting Vulnerability Scanner ===")
	logger.Info("Go version: %s", runtime.Version())
	logger.Info("OS/Architecture: %s/%s", runtime.GOOS, runtime.GOARCH)
	logger.Info("Available CPU cores: %d", runtime.NumCPU())
	logger.Info("Maximum workers: %d", *maxWorkers)
	logger.Info("Scan ID: %s", *scanId)

	// Load configuration
	config := map[string]interface{}{
		"source_dir":           *sourceDir,
		"rules_dir":           *rulesDir,
		"output_path":         *outputPath,
		"max_workers":         *maxWorkers,
		"timeout":             *timeout,
		"use_semgrep_registry": *useSemgrepRegistry,
		"verbose":             *verbose,
		"scan_id":             *scanId, // Include scan_id in config
	}

	// Load config file if provided
	if *configFile != "" {
		fileConfig, err := loadConfigFile(*configFile)
		if err != nil {
			logger.Error("Failed to load config file: %s", err)
			os.Exit(1)
		}
		// Merge file config with CLI args (CLI takes precedence)
		for key, value := range fileConfig {
			if _, exists := config[key]; !exists {
				config[key] = value
			}
		}
	}

	// Create detector
	detector := NewVulnerabilityDetector(config)

	// Run scan
	report, err := detector.ScanCodebase()
	if err != nil {
		logger.Critical("Scan failed: %v", err.Error())
		os.Exit(1)
	}

	// Print summary
	if summary, ok := report["summary"].(map[string]interface{}); ok {
		if total, ok := summary["total_vulnerabilities"].(int); ok {
			logger.Info("Scan completed. Found %d vulnerabilities", total)
			if severityBreakdown, ok := summary["severity_breakdown"].(map[string]int); ok {
				for severity, count := range severityBreakdown {
					if count > 0 {
						logger.Info("  %s: %d", severity, count)
					}
				}
			}
		}
	}

	if stats, ok := report["statistics"].(map[string]interface{}); ok {
		if filesProcessed, ok := stats["files_processed"].(int); ok { // Fixed: Corrected key from "files" to "files_processed"
			logger.Info("Files processed: %d", filesProcessed)
		}
		if rulesLoaded, ok := stats["rules_loaded"].(int); ok {
			logger.Info("Rules loaded: %d", rulesLoaded)
		}
		if scanDuration, ok := stats["scan_duration"].(int64); ok {
			logger.Info("Scan duration: %v", time.Duration(scanDuration))
		}
	}

	logger.Info("Vulnerability scan completed successfully")
}

func loadConfigFile(configPath string) (map[string]interface{}, error) {
	config := make(map[string]interface{})

	data, err := os.ReadFile(configPath)
	if err != nil {
		return config, err
	}

	ext := strings.ToLower(filepath.Ext(configPath))
	switch ext {
	case ".yaml", ".yml":
		err = yaml.Unmarshal(data, &config)
	case ".json":
		err = json.Unmarshal(data, &config)
	default:
		return config, fmt.Errorf("unsupported config file format: %s", ext)
	}

	return config, err
}