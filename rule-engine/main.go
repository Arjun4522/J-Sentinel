package main

import (
	//"bufio"
	"bytes"
	"crypto/md5"
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"context"
//	"io"
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
	"github.com/karrick/godirwalk"
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

type ScanStage string

const (
    StageDiscovering  ScanStage = "Discovering files"
    StageLoadingRules ScanStage = "Loading rules"
    StageScanning     ScanStage = "Scanning"
    StageAnalyzing    ScanStage = "Analyzing results"
    StageComplete     ScanStage = "Complete"
)

type ProgressTracker struct {
    currentStage    ScanStage
    stageStart      time.Time
    totalFiles      int
    filesDone       int
    currentFile     string
    mu              sync.Mutex
    lastUpdate      time.Time
    lastFileCount   int
    lastUpdateTime  time.Time
}

func (pt *ProgressTracker) UpdateStage(stage ScanStage) {
    pt.mu.Lock()
    defer pt.mu.Unlock()
    
    if pt.currentStage != "" {
        duration := time.Since(pt.stageStart)
        fmt.Fprintf(os.Stderr, "✔ %s completed in %v\n", pt.currentStage, duration.Round(time.Millisecond))
    }
    
    pt.currentStage = stage
    pt.stageStart = time.Now()
    pt.filesDone = 0 // Reset counter for new stage
    fmt.Fprintf(os.Stderr, "➔ %s...\n", stage)
}

func (pt *ProgressTracker) UpdateFileProgress(filePath string) {
    pt.mu.Lock()
    defer pt.mu.Unlock()
    
    now := time.Now()
    pt.filesDone++
    pt.currentFile = filepath.Base(filePath)
    
    // Calculate progress percentage
    progress := float64(pt.filesDone) / float64(pt.totalFiles)
    
    // Determine if we should update the display
    shouldUpdate := pt.filesDone == pt.totalFiles || 
                   now.Sub(pt.lastUpdate) > 200*time.Millisecond ||
                   int(progress*100) > int(float64(pt.lastFileCount)/float64(pt.totalFiles)*100+1)
    
    if pt.totalFiles > 0 && shouldUpdate {
        // Calculate ETA only if we've processed at least 5 files
        var eta string
        if pt.filesDone > 5 {
            elapsed := now.Sub(pt.stageStart)
            remaining := time.Duration(float64(elapsed) / float64(pt.filesDone) * float64(pt.totalFiles-pt.filesDone))
            if remaining > 0 {
                eta = fmt.Sprintf("ETA: %v", remaining.Round(time.Second))
            } else {
                eta = "Finishing..."
            }
        } else {
            eta = "Calculating..."
        }
        
        // Ensure we never show >100%
        displayPercent := math.Min(progress*100, 100)
        
        // Clear the line before printing new progress
        fmt.Fprintf(os.Stderr, "\r\033[K[%3.0f%%] %d/%d files | %s | %s", 
            displayPercent, 
            pt.filesDone, 
            pt.totalFiles,
            pt.currentFile,
            eta)
        
        pt.lastUpdate = now
        pt.lastFileCount = pt.filesDone
    }
    
    if pt.filesDone == pt.totalFiles {
        fmt.Fprintln(os.Stderr)
    }
}

type Rule struct {
	ID            string                 `yaml:"id" json:"id"`
	Category      string                 `yaml:"category" json:"category"`
	Type          string                 `yaml:"type" json:"type"`
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
	FilePath      string
}

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

type LanguagePatterns struct {
	Extensions []string          `json:"extensions"`
	Keywords   map[string]bool   `json:"keywords"`
	Imports    map[string]bool   `json:"imports"`
	DataTypes  map[string]bool   `json:"data_types"`
}

type LanguageDetector struct {
	patterns      map[string]LanguagePatterns
	extensionMap  map[string]string
	fileTypeCache sync.Map
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

	extensionMap := make(map[string]string)
	for lang, p := range patterns {
		for _, ext := range p.Extensions {
			extensionMap[ext] = lang
		}
	}

	return &LanguageDetector{
		patterns:     patterns,
		extensionMap: extensionMap,
	}
}

func (ld *LanguageDetector) DetectFromFile(filePath string) string {
	if lang, ok := ld.fileTypeCache.Load(filePath); ok {
		return lang.(string)
	}

	ext := strings.ToLower(filepath.Ext(filePath))
	if lang, exists := ld.extensionMap[ext]; exists {
		ld.fileTypeCache.Store(filePath, lang)
		return lang
	}

	file, err := os.Open(filePath)
	if err != nil {
		return "unknown"
	}
	defer file.Close()

	buf := make([]byte, 1024)
	n, _ := file.Read(buf)
	lang := ld.analyzeContent(string(buf[:n]))
	ld.fileTypeCache.Store(filePath, lang)
	return lang
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

type Statistics struct {
	FilesProcessed      int           `json:"files_processed"`
	RulesLoaded         int           `json:"rules_loaded"`
	VulnerabilitiesFound int          `json:"vulnerabilities_found"`
	ScanStartTime       *time.Time    `json:"scan_start_time"`
	ScanEndTime         *time.Time    `json:"scan_end_time"`
	ScanDuration        time.Duration `json:"scan_duration"`
}

type RuleCache struct {
	rules     []Rule
	timestamp time.Time
}

type VulnerabilityDetector struct {
	config             map[string]interface{}
	rules              map[string][]Rule
	ruleCache          map[string]*RuleCache
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
	fileQueue          chan string
	resultQueue        chan []Vulnerability
	progress           ProgressTracker
}

func NewVulnerabilityDetector(config map[string]interface{}) *VulnerabilityDetector {
	sourceDir := getStringConfig(config, "source_dir", ".")
	rulesDir := getStringConfig(config, "rules_dir", "rules")
	outputPath := getStringConfig(config, "output_path", "vulnerability_report.json")
	maxWorkers := getIntConfig(config, "max_workers", runtime.NumCPU())
	timeout := getIntConfig(config, "timeout", 300)
	useSemgrepRegistry := getBoolConfig(config, "use_semgrep_registry", false)

	detector := &VulnerabilityDetector{
		config:             config,
		rules:              make(map[string][]Rule),
		ruleCache:          make(map[string]*RuleCache),
		vulnerabilities:    []Vulnerability{},
		sourceDir:          sourceDir,
		outputPath:         outputPath,
		rulesDir:           rulesDir,
		maxWorkers:         maxWorkers,
		timeout:            timeout,
		useSemgrepRegistry: useSemgrepRegistry,
		languageDetector:   NewLanguageDetector(),
		stats:              Statistics{},
		fileQueue:          make(chan string, maxWorkers*10),
		resultQueue:        make(chan []Vulnerability, maxWorkers*10),
	}

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

func (vd *VulnerabilityDetector) discoverSourceFiles() ([]string, error) {
	var sourceFiles []string
	var mu sync.Mutex

	skipDirs := map[string]bool{
		"node_modules": true, "__pycache__": true, "venv": true, "env": true,
		"build": true, "dist": true, "target": true, ".git": true, ".svn": true,
		".hg": true, "vendor": true,
	}

	fileInfo, err := os.Stat(vd.sourceDir)
	if err != nil {
		return nil, fmt.Errorf("failed to stat source path %s: %w", vd.sourceDir, err)
	}

	if !fileInfo.IsDir() {
		ext := strings.ToLower(filepath.Ext(vd.sourceDir))
		if _, exists := vd.languageDetector.extensionMap[ext]; exists {
			return []string{vd.sourceDir}, nil
		}
		return nil, fmt.Errorf("single file %s has unsupported extension", vd.sourceDir)
	}

	err = godirwalk.Walk(vd.sourceDir, &godirwalk.Options{
		Unsorted: true,
		Callback: func(path string, de *godirwalk.Dirent) error {
			if de.IsDir() {
				if skipDirs[de.Name()] {
					return filepath.SkipDir
				}
				return nil
			}

			if ext := strings.ToLower(filepath.Ext(path)); ext != "" {
				if _, exists := vd.languageDetector.extensionMap[ext]; exists {
					mu.Lock()
					sourceFiles = append(sourceFiles, path)
					mu.Unlock()
				}
			}
			return nil
		},
		ErrorCallback: func(path string, err error) godirwalk.ErrorAction {
			logger.Debug("Error walking %s: %v", path, err)
			return godirwalk.SkipNode
		},
	})

	return sourceFiles, err
}

func (vd *VulnerabilityDetector) ScanCodebase() (map[string]interface{}, error) {
    startTime := time.Now()
    vd.stats.ScanStartTime = &startTime
    vd.progress.UpdateStage(StageDiscovering)
    
    logger.Debug("Discovering source files...")
    sourceFiles, err := vd.discoverSourceFiles()
    if err != nil {
        return nil, fmt.Errorf("failed to discover source files: %w", err)
    }

    vd.progress.totalFiles = len(sourceFiles)
    vd.progress.UpdateStage(StageLoadingRules)
    logger.Debug("Found %d source files", len(sourceFiles))
    if len(sourceFiles) == 0 {
        logger.Warning("No source files found to scan")
        return vd.generateReport(), nil
    }

    logger.Info("Found %d source files", len(sourceFiles))

    // Group files by language
    filesByLanguage := make(map[string][]string)
    for _, file := range sourceFiles {
        lang := vd.languageDetector.DetectFromFile(file)
        filesByLanguage[lang] = append(filesByLanguage[lang], file)
    }

    vd.progress.UpdateStage(StageScanning)
    
    ctx, cancel := context.WithTimeout(context.Background(), time.Duration(vd.timeout)*time.Second)
    defer cancel()

    var wg sync.WaitGroup
    resultChan := make(chan []Vulnerability, len(filesByLanguage))

    for lang, files := range filesByLanguage {
        wg.Add(1)
        go func(language string, fileList []string) {
            defer wg.Done()
            
            select {
            case <-ctx.Done():
                logger.Debug("Skipping language %s due to timeout", language)
                resultChan <- []Vulnerability{}
                return
            default:
                vulns := vd.batchProcessSemgrepRules(language, fileList)
                
                var regexWg sync.WaitGroup
                regexChan := make(chan []Vulnerability, len(fileList))
                
                for _, file := range fileList {
                    regexWg.Add(1)
                    go func(f string) {
                        defer regexWg.Done()
                        content, err := os.ReadFile(f)
                        if err != nil {
                            logger.Error("Failed to read file %s: %v", f, err)
                            regexChan <- []Vulnerability{}
                            return
                        }
                        
                        rules := vd.loadRules(language)
                        var regexRules []Rule
                        for _, rule := range rules {
                            if rule.Type == "regex" {
                                regexRules = append(regexRules, rule)
                            }
                        }
                        
                        regexChan <- vd.applyRulesToContent(regexRules, string(content), f, language)
                    }(file)
                }
                
                go func() {
                    regexWg.Wait()
                    close(regexChan)
                }()
                
                for regexVulns := range regexChan {
                    vulns = append(vulns, regexVulns...)
                }
                
                resultChan <- vulns
            }
        }(lang, files)
    }

    go func() {
        wg.Wait()
        close(resultChan)
    }()

    resultsDone := make(chan struct{})
    go func() {
        for vulns := range resultChan {
            vd.mu.Lock()
            vd.vulnerabilities = append(vd.vulnerabilities, vulns...)
            vd.stats.FilesProcessed += len(vulns)
            vd.mu.Unlock()
        }
        close(resultsDone)
    }()

    select {
    case <-resultsDone:
        logger.Debug("Finished processing all results")
    case <-ctx.Done():
        logger.Warning("Scan timed out after %d seconds", vd.timeout)
        return nil, fmt.Errorf("scan timed out after %d seconds", vd.timeout)
    }

    vd.progress.UpdateStage(StageAnalyzing)
    
    endTime := time.Now()
    vd.stats.ScanEndTime = &endTime
    vd.stats.ScanDuration = endTime.Sub(startTime)
    vd.stats.VulnerabilitiesFound = len(vd.vulnerabilities)

    report := vd.generateReport()
    vd.saveReport(report)
    
    vd.progress.UpdateStage(StageComplete)
    return report, nil
}


func (vd *VulnerabilityDetector) applyRulesToContent(rules []Rule, content, filePath, language string) []Vulnerability {
    vd.progress.UpdateFileProgress(filePath)
    
    var vulnerabilities []Vulnerability
    var mu sync.Mutex
    var wg sync.WaitGroup

    ruleChan := make(chan Rule, len(rules))
    resultChan := make(chan []Vulnerability, len(rules))

    for i := 0; i < min(vd.maxWorkers, len(rules)); i++ {
        wg.Add(1)
        go func() {
            defer wg.Done()
            for rule := range ruleChan {
                var vulns []Vulnerability
                if rule.Type == "regex" {
                    vulns = vd.applyRegexRule(rule, content, filePath)
                }
                resultChan <- vulns
            }
        }()
    }

    go func() {
        for _, rule := range rules {
            ruleChan <- rule
        }
        close(ruleChan)
    }()

    go func() {
        wg.Wait()
        close(resultChan)
    }()

    for vulns := range resultChan {
        mu.Lock()
        vulnerabilities = append(vulnerabilities, vulns...)
        mu.Unlock()
    }

    return vulnerabilities
}

func (vd *VulnerabilityDetector) loadRules(language string) []Rule {
    var rules []Rule
    var mu sync.Mutex
    langRulesDir := filepath.Join(vd.rulesDir, language)

    if _, err := os.Stat(langRulesDir); os.IsNotExist(err) {
        return rules
    }

    var ruleFiles []string
    err := godirwalk.Walk(langRulesDir, &godirwalk.Options{
        Unsorted: true,
        Callback: func(path string, de *godirwalk.Dirent) error {
            if !de.IsDir() && (strings.HasSuffix(strings.ToLower(path), ".yaml") || 
                strings.HasSuffix(strings.ToLower(path), ".yml")) {
                ruleFiles = append(ruleFiles, path)
            }
            return nil
        },
    })
    if err != nil {
        logger.Error("Error walking rules directory %s: %v", langRulesDir, err)
        return rules
    }

    var wg sync.WaitGroup
    fileChan := make(chan string, len(ruleFiles))
    resultChan := make(chan []Rule, len(ruleFiles))

    for i := 0; i < min(vd.maxWorkers, len(ruleFiles)); i++ {
        wg.Add(1)
        go func() {
            defer wg.Done()
            for path := range fileChan {
                fileRules, err := vd.loadRulesFromFile(path, language)
                if err != nil {
                    logger.Error("Error loading rule file %s: %v", path, err)
                    resultChan <- []Rule{}
                    continue
                }
                for i := range fileRules {
                    fileRules[i].FilePath = path
                }
                resultChan <- fileRules
            }
        }()
    }

    go func() {
        for _, path := range ruleFiles {
            fileChan <- path
        }
        close(fileChan)
    }()

    go func() {
        wg.Wait()
        close(resultChan)
    }()

    for fileRules := range resultChan {
        mu.Lock()
        rules = append(rules, fileRules...)
        vd.stats.RulesLoaded += len(fileRules)
        mu.Unlock()
    }

    return rules
}

func (vd *VulnerabilityDetector) loadRulesFromDisk(language string) []Rule {
	var rules []Rule
	var mu sync.Mutex
	langRulesDir := filepath.Join(vd.rulesDir, language)

	if _, err := os.Stat(langRulesDir); os.IsNotExist(err) {
		return rules
	}

	var ruleFiles []string
	err := godirwalk.Walk(langRulesDir, &godirwalk.Options{
		Unsorted: true,
		Callback: func(path string, de *godirwalk.Dirent) error {
			if !de.IsDir() && (strings.HasSuffix(strings.ToLower(path), ".yaml") || 
				strings.HasSuffix(strings.ToLower(path), ".yml")) {
				ruleFiles = append(ruleFiles, path)
			}
			return nil
		},
	})
	if err != nil {
		logger.Error("Error walking rules directory %s: %v", langRulesDir, err)
		return rules
	}

	var wg sync.WaitGroup
	fileChan := make(chan string, len(ruleFiles))
	resultChan := make(chan []Rule, len(ruleFiles))

	for i := 0; i < min(vd.maxWorkers, len(ruleFiles)); i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for path := range fileChan {
				fileRules, err := vd.loadRulesFromFile(path, language)
				if err != nil {
					resultChan <- []Rule{}
					continue
				}
				for i := range fileRules {
					fileRules[i].FilePath = path
				}
				resultChan <- fileRules
			}
		}()
	}

	go func() {
		for _, path := range ruleFiles {
			fileChan <- path
		}
		close(fileChan)
	}()

	go func() {
		wg.Wait()
		close(resultChan)
	}()

	for fileRules := range resultChan {
		mu.Lock()
		rules = append(rules, fileRules...)
		mu.Unlock()
	}

	return rules
}

func (vd *VulnerabilityDetector) loadRulesFromFile(filePath, language string) ([]Rule, error) {
    data, err := os.ReadFile(filePath)
    if err != nil {
        return nil, fmt.Errorf("failed to read rule file %s: %w", filePath, err)
    }

    var ruleData struct {
        Rules []map[string]interface{} `yaml:"rules"`
    }

    if err := yaml.Unmarshal(data, &ruleData); err != nil {
        return nil, fmt.Errorf("invalid YAML in rule file %s: %w", filePath, err)
    }

    var rules []Rule
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
    // This is now handled in batchProcessSemgrepRules
    return []Vulnerability{}
}

func (vd *VulnerabilityDetector) batchProcessSemgrepRules(language string, files []string) []Vulnerability {
    if len(files) == 0 {
        return []Vulnerability{}
    }

    /*for _, file := range files {
        vd.progress.UpdateFileProgress(file)
    }*/

    langRulesDir := filepath.Join(vd.rulesDir, language)
    if _, err := os.Stat(langRulesDir); os.IsNotExist(err) {
        logger.Debug("No rules directory for language %s", language)
        return []Vulnerability{}
    }

    hasSemgrepRules := false
    err := filepath.Walk(langRulesDir, func(path string, info os.FileInfo, err error) error {
        if err != nil {
            return err
        }
        if !info.IsDir() && (strings.HasSuffix(path, ".yaml") || strings.HasSuffix(path, ".yml")) {
            hasSemgrepRules = true
            return filepath.SkipDir
        }
        return nil
    })

    if err != nil || !hasSemgrepRules {
        logger.Debug("No Semgrep rules found for language %s", language)
        return []Vulnerability{}
    }

    args := []string{
        "semgrep",
        "--config", langRulesDir,
        "--json",
        "--quiet",
        "--timeout", strconv.Itoa(vd.timeout),
    }
    args = append(args, files...)

    logger.Debug("Executing Semgrep batch command for %s: %v", language, args)

    cmd := exec.Command(args[0], args[1:]...)
    var stdout, stderr bytes.Buffer
    cmd.Stdout = &stdout
    cmd.Stderr = &stderr

    startTime := time.Now()
    err = cmd.Run()
    duration := time.Since(startTime)

    if err != nil {
        if exitErr, ok := err.(*exec.ExitError); ok {
            if exitErr.ExitCode() != 1 {
                logger.Error("Batch semgrep failed for language %s with exit code %d: %s", 
                    language, exitErr.ExitCode(), stderr.String())
                return []Vulnerability{}
            }
        } else {
            logger.Error("Batch semgrep failed for language %s: %v, stderr: %s", 
                language, err, stderr.String())
            return []Vulnerability{}
        }
    }

    logger.Debug("Semgrep batch processing for %s completed in %v", language, duration)

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

    if err := json.Unmarshal(stdout.Bytes(), &semgrepOutput); err != nil {
        logger.Error("Failed to parse batch Semgrep JSON output for language %s: %v", language, err)
        return []Vulnerability{}
    }

    var vulnerabilities []Vulnerability
    for _, result := range semgrepOutput.Results {
        originalPath := result.Path
        if !filepath.IsAbs(originalPath) {
            absPath, err := filepath.Abs(originalPath)
            if err == nil {
                originalPath = absPath
            }
        }

        location := fmt.Sprintf("%s:%d:%d", filepath.Base(originalPath), result.Start.Line, result.Start.Col)
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
                "file_path": originalPath,
                "lines":     result.Extra.Lines,
                "semgrep":   true,
                "batch":     true,
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

    logger.Debug("Found %d vulnerabilities for language %s", len(vulnerabilities), language)
    return vulnerabilities
}

func (vd *VulnerabilityDetector) executeSemgrep(rulesFile, sourceFile, originalFile, language string) []Vulnerability {
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

	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			logger.Error("Semgrep failed for rule file %s with exit code %d: %s", 
				rulesFile, exitErr.ExitCode(), stderr.String())
		} else {
			logger.Error("Semgrep failed for rule file %s: %v, stderr: %s", 
				rulesFile, err, stderr.String())
		}
		return []Vulnerability{}
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

	if err := json.Unmarshal(stdout.Bytes(), &semgrepOutput); err != nil {
		logger.Error("Failed to parse Semgrep JSON output for rule file %s: %v", rulesFile, err)
		return []Vulnerability{}
	}

	var vulnerabilities []Vulnerability
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
	if !vd.useSemgrepRegistry {
		return []Vulnerability{}
	}

	tmpDir, err := os.MkdirTemp("", "semgrep_registry_*")
	if err != nil {
		logger.Error("Failed to create temp directory: %v", err)
		return []Vulnerability{}
	}
	defer os.RemoveAll(tmpDir)

	ext := vd.languageDetector.GetFileExtension(language)
	sourceFile := filepath.Join(tmpDir, "source"+ext)
	if err := os.WriteFile(sourceFile, []byte(content), 0644); err != nil {
		logger.Error("Failed to create temp source file: %v", err)
		return []Vulnerability{}
	}

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

	var vulnerabilities []Vulnerability
	var mu sync.Mutex
	var wg sync.WaitGroup

	rulesetChan := make(chan string, len(rulesets))
	resultChan := make(chan []Vulnerability, len(rulesets))

	for i := 0; i < min(vd.maxWorkers, len(rulesets)); i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ruleset := range rulesetChan {
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

				if err := cmd.Run(); err != nil {
					logger.Debug("Semgrep registry scan failed for %s: %v, stderr: %s", 
						ruleset, err, stderr.String())
					resultChan <- []Vulnerability{}
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

				if err := json.Unmarshal(stdout.Bytes(), &semgrepOutput); err != nil {
					logger.Error("Failed to parse Semgrep registry output for %s: %v", ruleset, err)
					resultChan <- []Vulnerability{}
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
				resultChan <- ruleVulns
			}
		}()
	}

	go func() {
		for _, ruleset := range rulesets {
			rulesetChan <- ruleset
		}
		close(rulesetChan)
	}()

	go func() {
		wg.Wait()
		close(resultChan)
	}()

	for ruleVulns := range resultChan {
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

    // Get scan ID from config
    scanID := getStringConfig(vd.config, "scan_id", uuid.New().String())

    report := map[string]interface{}{
        "scan_id":            scanID,
        "timestamp":          time.Now().Format(time.RFC3339),
        "source_directory":   vd.sourceDir,
        "statistics": map[string]interface{}{
            "files_processed":        vd.stats.FilesProcessed,
            "rules_loaded":          vd.stats.RulesLoaded,
            "vulnerabilities_found":  vd.stats.VulnerabilitiesFound,
            "scan_start_time":        vd.stats.ScanStartTime.Format(time.RFC3339Nano),
            "scan_end_time":         vd.stats.ScanEndTime.Format(time.RFC3339Nano),
            "scan_duration":          int64(vd.stats.ScanDuration),
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
                "timeout":             vd.timeout,
                "use_semgrep_registry": vd.useSemgrepRegistry,
            },
        },
    }

    return report
}

func (vd *VulnerabilityDetector) saveReportSummary(report map[string]interface{}, summaryPath string) {
    var summary strings.Builder
    summary.WriteString("=== VULNERABILITY SCAN SUMMARY ===\n\n")

    if timestamp, ok := report["timestamp"].(string); ok {
        summary.WriteString(fmt.Sprintf("Scan Timestamp: %s\n", timestamp))
    }

    if sourceDir, ok := report["source_directory"].(string); ok {
        summary.WriteString(fmt.Sprintf("Source Directory: %s\n", sourceDir))
    }

    summary.WriteString("\n")

    if summaryData, ok := report["summary"].(map[string]interface{}); ok {
        if total, ok := summaryData["total_vulnerabilities"].(int); ok {
            summary.WriteString(fmt.Sprintf("Total Vulnerabilities: %d\n\n", total))
        }

        if severityBreakdown, ok := summaryData["severity_breakdown"].(map[string]int); ok {
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
        logger.Error("Failed to save summary report: %v", err)
    } else {
        logger.Info("Summary report saved to %s", summaryPath)
    }
}

func (vd *VulnerabilityDetector) saveReport(report map[string]interface{}) {
    // Get scan ID from config
    scanID := getStringConfig(vd.config, "scan_id", uuid.New().String())
    
    // Create reports directory if it doesn't exist
    reportsDir := "./reports"
    if err := os.MkdirAll(reportsDir, 0755); err != nil {
        logger.Error("Failed to create reports directory %s: %v", reportsDir, err)
        return
    }

    // Generate report paths inside the reports directory
    reportPath := filepath.Join(reportsDir, fmt.Sprintf("%s.json", scanID))

    // Save JSON report
    reportJSON, err := json.MarshalIndent(report, "", "  ")
    if err != nil {
        logger.Error("Failed to marshal report to JSON: %v", err)
        return
    }
    
    if err = os.WriteFile(reportPath, reportJSON, 0644); err != nil {
        logger.Error("Failed to save JSON report to %s: %v", reportPath, err)
        return
    }
    logger.Info("JSON report saved to %s", reportPath)

    // Initialize database connection
    db, err := NewDB(filepath.Dir(vd.outputPath))
    if err != nil {
        logger.Error("Failed to initialize database: %v", err)
        return
    }
    defer db.Close()

    // Insert scan data with all required fields
    _, err = db.conn.Exec(`
        INSERT INTO scans (
            scanId, source_directory, filesProcessed, 
            vulnerabilitiesFound, duration, timestamp
        ) VALUES (?, ?, ?, ?, ?, ?)`,
        scanID,
        vd.sourceDir, // source_directory
        vd.stats.FilesProcessed,
        vd.stats.VulnerabilitiesFound,
        int64(vd.stats.ScanDuration),
        time.Now().Format(time.RFC3339), // timestamp
    )
    if err != nil {
        logger.Error("Failed to insert scan data for scan ID %s: %v", scanID, err)
        return
    }

	// Update directory history
_, err = db.conn.Exec(`
    INSERT INTO directory_history (
        directory, first_scan, last_scan, scan_count
    ) VALUES (?, ?, ?, 1)
    ON CONFLICT(directory) DO UPDATE SET
        last_scan = excluded.last_scan,
        scan_count = scan_count + 1`, 
    vd.sourceDir, // directory
    time.Now().Format(time.RFC3339), // first_scan (for new entries)
    time.Now().Format(time.RFC3339), // last_scan
	)
	if err != nil {
    	logger.Error("Failed to update directory history: %v", err)
	}

    logger.Info("Report saved to database with scan ID: %s", scanID)
}

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

func main() {
	var (
		sourceDir          = flag.String("source", ".", "Source code directory to scan")
		rulesDir           = flag.String("rules", "rules", "Rules directory")
		outputPath         = flag.String("output", "vulnerability_report.json", "Output file path")
		maxWorkers         = flag.Int("workers", runtime.NumCPU(), "Maximum number of worker goroutines")
		timeout            = flag.Int("timeout", 300, "Timeout for individual scans in seconds")
		useSemgrepRegistry = flag.Bool("semgrep-registry", false, "Use Semgrep registry rules")
		verbose            = flag.Bool("verbose", false, "Enable verbose logging")
		configFile         = flag.String("config", "", "Configuration file path")
		scanId             = flag.String("scan_id", uuid.New().String(), "Unique identifier for the scan")
	)
	flag.Parse()

	logger = NewLogger(*verbose)

	logger.Info("=== Starting Vulnerability Scanner ===")
	logger.Info("Go version: %s", runtime.Version())
	logger.Info("OS/Architecture: %s/%s", runtime.GOOS, runtime.GOARCH)
	logger.Info("Available CPU cores: %d", runtime.NumCPU())
	logger.Info("Maximum workers: %d", *maxWorkers)
	logger.Info("Scan ID: %s", *scanId)

	config := map[string]interface{}{
		"source_dir":           *sourceDir,
		"rules_dir":           *rulesDir,
		"output_path":         *outputPath,
		"max_workers":         *maxWorkers,
		"timeout":             *timeout,
		"use_semgrep_registry": *useSemgrepRegistry,
		"verbose":             *verbose,
		"scan_id":             *scanId,
	}

	if *configFile != "" {
		fileConfig, err := loadConfigFile(*configFile)
		if err != nil {
			logger.Error("Failed to load config file: %s", err)
			os.Exit(1)
		}
		for key, value := range fileConfig {
			if _, exists := config[key]; !exists {
				config[key] = value
			}
		}
	}

	detector := NewVulnerabilityDetector(config)
	report, err := detector.ScanCodebase()
	if err != nil {
		logger.Critical("Scan failed: %v", err.Error())
		os.Exit(1)
	}

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
		if filesProcessed, ok := stats["files_processed"].(int); ok {
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