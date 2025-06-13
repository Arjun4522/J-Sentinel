# 🛡️ J-Sentinel: Multi-Language Static Code Analysis Tool

🔍 A comprehensive static code analysis platform featuring rule-based pattern matching, vulnerability detection, and multi-language support with an integrated API Gateway for enterprise-grade security analysis.

## 📋 Table of Contents

- [Overview](#-overview)
- [Architecture](#️-architecture)
- [Features](#-features)
- [Installation](#-installation)
- [Usage](#-usage)
- [Rule Engine](#-rule-engine)
- [API Reference](#-api-reference)
- [Configuration](#️-configuration)
- [Examples](#-examples)
- [Multi-Language Support](#-multi-language-support)
- [Contributing](#-contributing)
- [Troubleshooting](#-troubleshooting)

## 🎯 Overview

J-Sentinel is a powerful multi-language static analysis platform designed to enhance application security through advanced rule-based pattern matching and vulnerability detection. The tool combines custom rule engines with optional Semgrep integration to provide comprehensive security insights for Java, C/C++, and other programming languages.

## 🏗️ Architecture

J-Sentinel consists of four main components:

### Core Components
- **🔍 Rule Engine**: Advanced pattern matching system with custom rules and Semgrep integration
- **📊 Multi-Language Parsers**: Java, C/C++ code analysis with extensible parser architecture
- **🌐 API Gateway**: Spring Boot service for managing scans, rules, and analysis results
- **📈 Code Graph Analysis**: Optional detailed code graph construction for advanced analysis

### Analysis Engines
- **🎯 Rule-Based Detection**: Custom pattern matching with configurable rule sets
- **🔧 Semgrep Integration**: Industry-standard rule registry support
- **🌳 Code Graph Generator**: Creates interconnected representations of code elements
- **🔄 Control Flow Analyzer**: Tracks program execution paths
- **📈 Data Flow Analyzer**: Analyzes data movement and transformations

## ✨ Features

### 🔐 Rule-Based Security Analysis
- **Custom Rule Engine**: Flexible pattern matching with YAML-based rule definitions
- **Semgrep Integration**: Access to comprehensive security rule registry
- **Multi-Language Support**: Java, C/C++, with extensible architecture
- **Real-time Scanning**: API-driven analysis with immediate results
- **Rule Management**: Dynamic rule loading and configuration

### 🚨 Vulnerability Detection
- **Security Vulnerabilities**: SQL injection, XSS, CSRF, and more
- **Code Quality Issues**: Performance bottlenecks, code smells
- **Compliance Checks**: OWASP, CWE, and custom compliance rules
- **Input Validation**: Missing validation and sanitization detection
- **Sensitive Data Exposure**: Credential and PII leak detection

### 📊 Advanced Analysis (Optional)
- **Code Graph Generation**: Detailed code structure representation
- **Taint Analysis**: Data flow vulnerability tracking
- **Control Flow Analysis**: Program execution path analysis
- **Data Flow Analysis**: Variable and data transformation tracking

## 📦 Installation

### Prerequisites

Ensure you have the following installed:
- ☕ **Java 17+** - Main runtime environment
- 🔧 **Maven 3.6+** - Build and dependency management
- 🐍 **Python 3.8+** - Rule engine and Semgrep integration
- 🛠️ **CMake 3.15+** - C/C++ parser compilation
- 📦 **Semgrep** - Optional, for extended rule support

### Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/arjun4522/j-sentinel.git
   cd j-sentinel
   ```

2. **Set up environment variables:**
   ```bash
   export CLASSPATH=".:/home/arjun/Desktop/J-Sentinel:/home/arjun/.m2/repository/com/github/javaparser/javaparser-core/3.26.2/javaparser-core-3.26.2.jar:/home/arjun/.m2/repository/org/json/json/20240303/json-20240303.jar:/home/arjun/.m2/repository/org/jgrapht/jgrapht-core/1.5.2/jgrapht-core-1.5.2.jar:/home/arjun/.m2/repository/org/jheaps/jheaps/0.14/jheaps-0.14.jar:/home/arjun/.m2/repository/org/apfloat/apfloat/1.10.1/apfloat-1.10.1.jar"
   export API_USER=user
   export API_PASSWORD=secret
   ```

3. **Create required directories:**
   ```bash
   mkdir -p /tmp/j-sentinel/uploads /tmp/j-sentinel/outputs
   chmod -R 777 /tmp/j-sentinel
   ```

4. **Install Python dependencies:**
   ```bash
   pip install semgrep pyyaml requests
   ```

5. **Build components:**
   ```bash
   # Java components
   mkdir -p lib
   cp ~/.m2/repository/com/github/javaparser/javaparser-core/3.26.2/javaparser-core-3.26.2.jar lib/
   cp ~/.m2/repository/org/json/json/20240303/json-20240303.jar lib/
   cp ~/.m2/repository/org/jgrapht/jgrapht-core/1.5.2/jgrapht-core-1.5.2.jar lib/
   cp ~/.m2/repository/org/jheaps/jheaps/0.14/jheaps-0.14.jar lib/
   cp ~/.m2/repository/org/apfloat/apfloat/1.10.1/apfloat-1.10.1.jar lib/
   
   javac -cp "lib/*" scanner.java analyse_test.java cfg_extract.java dfg_extract.java
   
   # C/C++ parser
   cd cpp-parser/build
   cmake ../
   make
   cd ../..
   
   # Rule engine
   cd rule-engine
   ./build.sh
   cd ..
   ```

6. **Start the API Gateway:**
   ```bash
   cd api-gateway
   ./mvnw spring-boot:run
   ```

## 🚀 Usage

### Rule Engine (Primary Usage)

The rule engine is the core component of J-Sentinel, providing comprehensive security analysis through pattern matching.

#### Direct Rule Engine Usage
```bash
# Run with custom rules
python3 rule-engine/detect_test.py -s test/ -r rule-engine/rules -v --log-file debug.log

# Run with Semgrep registry
python3 rule-engine/detect_test.py -s test/ -r rule-engine/rules -v --log-file debug.log --use-semgrep-registry

# Compiled binary usage
cd rule-engine
./detect --source=../test/
```

#### API-Driven Analysis (Recommended)
```bash
# Trigger comprehensive security scan
curl -u user:secret -X POST http://localhost:8080/api/scan/trigger \
-H "Content-Type: application/json" \
-d '{
  "sourceDir": "/path/to/your/code",
  "rulesDir": "/path/to/j-sentinel/rule-engine/rules",
  "timeout": 300,
  "useSemgrep": false
}'

# Check scan status
curl -u user:secret http://localhost:8080/api/scans/status/<scan-id>

# Get detailed report
curl -u user:secret http://localhost:8080/api/scans/<scan-id>/report
```

### Multi-Language Analysis

#### Java Analysis
```bash
# CLI approach
./jsentinel.sh scan --input test/ --endpoint http://localhost:8080/api --user user --password secret --output output/scan.json
./jsentinel.sh taint --endpoint http://localhost:8080/api --user user --password secret --output output/taint_analysis.json
```

#### C/C++ Analysis
```bash
cd cpp-parser/build
./cpp_scanner ../test_code.cpp --local --output=../../output/codegraph_cpp.json
```

## 🎯 Rule Engine

The rule engine is the heart of J-Sentinel's security analysis capabilities.

### Rule Structure
Rules are defined in YAML format with the following structure:
```yaml
rules:
  - id: "security.sql-injection"
    message: "Potential SQL injection vulnerability"
    severity: "high"
    languages: ["java", "javascript"]
    pattern: |
      String query = "SELECT * FROM users WHERE id = " + $VAR;
    fix: "Use parameterized queries instead"
```

### Rule Categories
- **Security**: SQL injection, XSS, CSRF, authentication bypasses
- **Privacy**: PII exposure, credential leaks, data handling
- **Performance**: Inefficient algorithms, memory leaks, resource usage
- **Quality**: Code smells, maintainability issues, best practices
- **Compliance**: OWASP, CWE, industry-specific standards

### Custom Rule Development
1. Create rule files in `rule-engine/rules/`
2. Follow the YAML schema for rule definitions
3. Test rules with sample vulnerable code
4. Deploy through API Gateway for team usage

### Semgrep Integration
Enable industry-standard rules:
```bash
# Install Semgrep
pip install semgrep

# Run with registry rules
python3 detect_test.py --use-semgrep-registry
```

## 🔌 API Reference

### Rule Engine Endpoints

| Method | Endpoint | Description | Parameters |
|--------|----------|-------------|------------|
| `POST` | `/api/scan/trigger` | Trigger security scan | `sourceDir`, `rulesDir`, `timeout`, `useSemgrep` |
| `GET` | `/api/scans/status/<id>` | Get scan status | `id` (path) |
| `GET` | `/api/scans/<id>/report` | Get scan report | `id` (path) |
| `GET` | `/api/scans/<id>/metadata` | Get scan metadata | `id` (path) |
| `GET` | `/api/scans` | List all scans | - |

### Code Graph Endpoints (Optional)

| Method | Endpoint | Description | Parameters |
|--------|----------|-------------|------------|
| `POST` | `/api/scan` | Upload code graph | `file` (multipart) |
| `GET` | `/api/graph` | Retrieve code graph | `scanId` (query) |
| `GET` | `/api/cfg_extract` | Get Control Flow Graph | `scanId` (query) |
| `GET` | `/api/dfg_extract` | Get Data Flow Graph | `scanId` (query) |
| `GET` | `/api/taint_analyse` | Get taint analysis | `scanId` (query) |

### Authentication
Uses HTTP Basic Authentication:
- **Username**: `user` (or `API_USER` env var)
- **Password**: `secret` (or `API_PASSWORD` env var)

## ⚙️ Configuration

### API Gateway Configuration
Edit `api-gateway/src/main/resources/application.properties`:
```properties
server.port=8080
spring.servlet.multipart.max-file-size=10MB
spring.servlet.multipart.max-request-size=10MB
app.upload.dir=/tmp/j-sentinel/uploads
app.output.dir=/tmp/j-sentinel/outputs
app.rules.dir=/path/to/rule-engine/rules
app.semgrep.enabled=true
```

### Rule Engine Configuration
Configure rule engine behavior:
```yaml
# rule-engine/config.yml
engine:
  timeout: 300
  max_file_size: 10MB
  supported_languages: ["java", "cpp", "javascript", "python"]
  semgrep:
    enabled: true
    registry_url: "https://semgrep.dev/c/r/all"
```

## 📊 Examples

### Complete Security Analysis Workflow

1. **Start API Gateway**:
   ```bash
   cd api-gateway && ./mvnw spring-boot:run
   ```

2. **Trigger Comprehensive Scan**:
   ```bash
   curl -u user:secret -X POST http://localhost:8080/api/scan/trigger \
   -H "Content-Type: application/json" \
   -d '{
     "sourceDir": "/home/user/my-project/src",
     "rulesDir": "/home/user/j-sentinel/rule-engine/rules",
     "timeout": 300,
     "useSemgrep": true
   }'
   ```

3. **Monitor Progress**:
   ```bash
   # Response contains scan ID, e.g., "2a96d0e7-c8d2-4efd-8526-a552fb46f421"
   curl -u user:secret http://localhost:8080/api/scans/status/2a96d0e7-c8d2-4efd-8526-a552fb46f421
   ```

4. **Retrieve Results**:
   ```bash
   curl -u user:secret http://localhost:8080/api/scans/2a96d0e7-c8d2-4efd-8526-a552fb46f421/report
   ```

5. **Track All Scans**:
   ```bash
   curl -u user:secret http://localhost:8080/api/scans
   ```

### Sample Output
```json
{
  "scanId": "2a96d0e7-c8d2-4efd-8526-a552fb46f421",
  "status": "completed",
  "findings": [
    {
      "ruleId": "security.sql-injection",
      "severity": "high",
      "file": "src/main/java/UserService.java",
      "line": 42,
      "message": "Potential SQL injection vulnerability",
      "code": "String query = \"SELECT * FROM users WHERE id = \" + userId;"
    }
  ],
  "summary": {
    "totalFiles": 15,
    "totalFindings": 8,
    "highSeverity": 2,
    "mediumSeverity": 4,
    "lowSeverity": 2
  }
}
```

## 🌍 Multi-Language Support

### Java
- **Parser**: JavaParser-based AST analysis
- **Features**: Full language support, framework-specific rules
- **Rules**: Spring Security, JPA, Servlet vulnerabilities

### C/C++
- **Parser**: Clang-based analysis
- **Features**: Memory safety, buffer overflows, use-after-free
- **Rules**: CERT C/C++, MISRA compliance

### Extensible Architecture
Add new language support by:
1. Implementing parser interface
2. Adding language-specific rules
3. Updating API Gateway configuration


## 🔧 Troubleshooting

### Rule Engine Issues
1. **Python Dependencies**:
   ```bash
   pip install semgrep pyyaml requests
   ```

2. **Rule Loading Errors**:
   ```bash
   # Check rule syntax
   python3 -c "import yaml; yaml.safe_load(open('rule-engine/rules/security.yml'))"
   ```

3. **Semgrep Integration**:
   ```bash
   semgrep --version
   semgrep --config=auto test/
   ```

### API Gateway Issues
1. **Connection Problems**:
   ```bash
   curl -u user:secret http://localhost:8080/api/health
   ```

2. **Scan Status**:
   ```bash
   curl -u user:secret http://localhost:8080/api/scans
   ```

3. **Permission Errors**:
   ```bash
   chmod -R 777 /tmp/j-sentinel
   ```

### Build Issues
1. **Java Compilation**:
   ```bash
   javac -cp "lib/*" scanner.java
   ```

2. **C++ Parser**:
   ```bash
   cd cpp-parser/build && cmake ../ && make
   ```

3. **Missing Dependencies**:
   ```bash
   ls -l lib/
   echo $CLASSPATH
   ```


- **Issue Tracker**: [GitHub Issues](https://github.com/arjun4522/j-sentinel/issues)
