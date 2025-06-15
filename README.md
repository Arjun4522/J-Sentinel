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

J-Sentinel is a powerful multi-language static analysis platform designed to enhance application security through advanced rule-based pattern matching and vulnerability detection. The tool combines custom rule engines with optional Semgrep integration to provide comprehensive security insights for Java, C/C++, Java, and other programming languages.

## 🏗️ Architecture

J-Sentinel consists of three main components:

### Core Components
- **🔍 Rule Engine**: Advanced pattern matching system with custom rules and Semgrep integration
- **🌐 API Gateway**: Spring Boot service for managing scans, rules, and analysis results
- **🗄️ Database**: SQLite database for persistent scan history and tracking

### Analysis Engines
- **🎯 Rule-Based Detection**: Custom pattern matching with configurable rule sets
- **🔧 Semgrep Integration**: Industry-standard rule registry support

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

### 📊 Scan Management
- **Persistent History**: SQLite database for scan tracking
- **Real-time Status**: Monitor scan progress and completion
- **Comprehensive Reports**: Detailed vulnerability analysis with severity levels
- **Directory Tracking**: Track scans by source directory

## 📦 Installation

### Prerequisites

Ensure you have the following installed:
- ☕ **Java 17+** - Main runtime environment
- 🔧 **Maven 3.6+** - Build and dependency management
- 🐍 **Python 3.8+** - Rule engine and Semgrep integration
- 🗄️ **SQLite** - Database for scan history
- 📦 **Semgrep** - Optional, for extended rule support
- 🔧 **Go** - For rule engine binary compilation

### Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/arjun4522/j-sentinel.git
   cd j-sentinel
   ```

2. **Set up environment variables:**
   ```bash
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

5. **Set up SQLite database:**
   ```bash
   go run initdb.go db_setup.go
   # Verify database creation
   sqlite3 reports/data.db
   ```

6. **Build rule engine:**
   ```bash
   cd rule-engine
   ./build.sh
   cd ..
   ```

7. **Build and start the API Gateway:**
   ```bash
   cd api-gateway
   ./mvnw clean install
   ./mvnw spring-boot:run
   ```

## 🚀 Usage

### Rule Engine (Primary Usage)

The rule engine is the core component of J-Sentinel, providing comprehensive security analysis through pattern matching.

#### API-Driven Analysis (Recommended)
```bash
# Trigger comprehensive security scan
curl -u user:secret -X POST http://localhost:8080/api/scan/trigger \
-H "Content-Type: application/json" \
-d '{
  "sourceDir": "/home/arjun/Desktop/J-Sentinel/test",
  "rulesDir": "/home/arjun/Desktop/J-Sentinel/rule-engine/rules",
  "timeout": 300,
  "useSemgrep": false
}'

# Get all scans
curl -u user:secret http://localhost:8080/api/scans

# Get specific scan metadata
curl -u user:secret http://localhost:8080/api/scans/2a96d0e7-c8d2-4efd-8526-a552fb46f421/metadata

# Get detailed report
curl -u user:secret http://localhost:8080/api/scans/2a96d0e7-c8d2-4efd-8526-a552fb46f421/report
```

#### Direct Rule Engine Usage
```bash
# Run with custom rules
python3 rule-engine/detect_test.py -s test/ -r rule-engine/rules -v --log-file debug.log

# Run with Semgrep registry
python3 rule-engine/detect_test.py -s test/ -r rule-engine/rules -v --log-file debug.log --use-semgrep-registry

# Binary usage
cd rule-engine
./detect --source=../test/
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

### Scan Management Endpoints

| Method | Endpoint | Description | Parameters |
|--------|----------|-------------|------------|
| `POST` | `/api/scan/trigger` | Trigger security scan | `sourceDir`, `rulesDir`, `timeout`, `useSemgrep` |
| `GET` | `/api/scans` | Get all scans | - |
| `GET` | `/api/scans/<id>/metadata` | Get scan metadata | `id` (path) |
| `GET` | `/api/scans/<id>/report` | Get scan report | `id` (path) |

### History Endpoints

| Method | Endpoint | Description | Parameters |
|--------|----------|-------------|------------|
| `GET` | `/api/history/scans` | Get all scan history | - |
| `GET` | `/api/history/directory/<path>` | Get directory scan history | `path` (URL encoded) |

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
     "sourceDir": "/home/arjun/Desktop/J-Sentinel/test",
     "rulesDir": "/home/arjun/Desktop/J-Sentinel/rule-engine/rules",
     "timeout": 300,
     "useSemgrep": false
   }'
   ```

3. **Track All Scans**:
   ```bash
   curl -u user:secret http://localhost:8080/api/scans
   ```

4. **Get Specific Scan Details**:
   ```bash
   # Get metadata
   curl -u user:secret http://localhost:8080/api/scans/2a96d0e7-c8d2-4efd-8526-a552fb46f421/metadata
   
   # Get full report
   curl -u user:secret http://localhost:8080/api/scans/2a96d0e7-c8d2-4efd-8526-a552fb46f421/report
   ```

5. **View Scan History**:
   ```bash
   # All scan history
   curl -u user:secret http://localhost:8080/api/history/scans
   
   # Directory-specific history (URL encoded path)
   curl -u user:secret "http://localhost:8080/api/history/directory/%2Fprojects%2Fmyapp"
   
   # Pretty-printed with jq
   curl -s -u user:secret http://localhost:8080/api/history/scans | jq
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
- **Features**: Full language support, framework-specific rules
- **Rules**: Spring Security, JPA, Servlet vulnerabilities

### C/C++
- **Features**: Memory safety, buffer overflows, use-after-free
- **Rules**: CERT C/C++, MISRA compliance

### Extensible Architecture
Add new language support by:
1. Adding language-specific rules to `rule-engine/rules/`
2. Updating API Gateway configuration
3. Testing with sample code

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

4. **Binary Build Issues**:
   ```bash
   cd rule-engine
   ./build.sh
   ./detect --source=../test/
   ```

### API Gateway Issues
1. **Connection Problems**:
   ```bash
   curl -u user:secret http://localhost:8080/api/health
   ```

2. **Database Issues**:
   ```bash
   # Check database
   sqlite3 reports/data.db
   # Reinitialize if needed
   go run initdb.go db_setup.go
   ```

3. **Permission Errors**:
   ```bash
   chmod -R 777 /tmp/j-sentinel
   ```

### Build Issues
1. **Maven Build**:
   ```bash
   cd api-gateway
   ./mvnw clean install
   ```

2. **Go Binary**:
   ```bash
   cd rule-engine
   ./build.sh
   ```

3. **Database Setup**:
   ```bash
   go run initdb.go db_setup.go
   ```

## 🤝 Contributing

We welcome contributions to J-Sentinel! Please follow these guidelines:

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

### Development Setup
1. Follow the installation instructions
2. Set up your development environment
3. Run tests to ensure everything works
4. Make your changes and test thoroughly

For detailed contributing guidelines, please see our [CONTRIBUTING.md](CONTRIBUTING.md) file.

---
