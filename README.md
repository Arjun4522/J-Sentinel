# 🛡️ J-Sentinel: Java Code Analysis Tool

🔍 A comprehensive Java static code analysis tool that performs taint analysis and vulnerability detection through detailed code graph construction.

## 📋 Table of Contents

- [Overview](#-overview)
- [Architecture](#️-architecture)
- [Features](#-features)
- [Installation](#-installation)
- [Usage](#-usage)
- [API Reference](#-api-reference)
- [Configuration](#️-configuration)
- [Examples](#-examples)
- [Visualization](#-visualization)
- [Contributing](#-contributing)

## 🎯 Overview

J-Sentinel is a powerful static analysis tool designed to enhance application security by detecting vulnerabilities through advanced code graph analysis. It combines multiple analysis techniques to provide comprehensive security insights for Java applications.

## 🏗️ Architecture

J-Sentinel consists of three main components:

### Core Components
- **🔍 Scanner**: Parses Java source code and constructs detailed code graphs
- **⚡ Analyzer**: Performs sophisticated taint analysis for vulnerability detection  
- **🌐 API Gateway**: Spring Boot service for storing and serving analysis results

### Analysis Engines
- **🌳 Code Graph Generator**: Creates interconnected representations of code elements
- **🔄 Control Flow Analyzer**: Tracks program execution paths
- **📈 Data Flow Analyzer**: Analyzes data movement and transformations
- **🌲 AST Parser**: Provides structural code representation

## ✨ Features

### 📊 Code Analysis Capabilities
- **Code Graph Generation**: Represents code elements as interconnected nodes and edges
- **Control Flow Graph (CFG)**: Tracks program execution paths
- **Data Flow Graph (DFG)**: Analyzes data movement and transformations
- **Abstract Syntax Tree (AST)**: Provides structural code representation

### 🔐 Security Vulnerability Detection
- **Log Injection Vulnerabilities**: Detects unsafe logging practices
- **Missing Input Validations**: Identifies unvalidated user inputs
- **Inefficient List Operations**: Spots performance bottlenecks
- **Sensitive Data Exposures**: Finds potential data leaks
- **Overly Broad Exception Catches**: Identifies poor error handling

## 📦 Installation

### Prerequisites

Ensure you have the following installed:

- ☕ **Java 17+** - Main runtime environment
- 🔧 **Maven 3.6+** - Build and dependency management
- 🐍 **Python 3.8+** - For visualization capabilities (optional)

### Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/arjun4522/j-sentinel.git
   cd j-sentinel
   ```

2. **Set up environment variables:**
   ```bash
   export CLASSPATH=".:/path/to/j-sentinel:/home/user/.m2/repository/com/github/javaparser/javaparser-core/3.26.2/javaparser-core-3.26.2.jar:/home/user/.m2/repository/org/json/json/20240303/json-20240303.jar:/home/user/.m2/repository/org/jgrapht/jgrapht-core/1.5.2/jgrapht-core-1.5.2.jar:/home/user/.m2/repository/org/jheaps/jheaps/0.14/jheaps-0.14.jar:/home/user/.m2/repository/org/apfloat/apfloat/1.10.1/apfloat-1.10.1.jar"
   
   export API_USER=user
   export API_PASSWORD=secret
   ```

3. **Create required directories:**
   ```bash
   mkdir -p /tmp/j-sentinel/uploads /tmp/j-sentinel/outputs
   chmod -R 777 /tmp/j-sentinel
   ```

4. **Compile the components:**
   ```bash
   javac -cp "$CLASSPATH" scanner.java
   javac -cp "$CLASSPATH" analyse.java
   javac -cp "$CLASSPATH" scanner_test.java
   javac -cp "$CLASSPATH" analyse_test.java
   ```

## 🚀 Usage

### 🔍 Scanner Usage

The scanner parses Java source code and generates code graphs.

```bash
java -cp "$CLASSPATH" scanner <path-to-java-source> [options]
```

#### Scanner Options
| Option | Description | Default |
|--------|-------------|---------|
| `--local` | Save output locally instead of uploading to API | Upload to API |
| `--output <path>` | Specify output file path | `codegraph.json` |
| `--endpoint <url>` | Custom API endpoint URL | `http://localhost:8080/api/scan` |

#### Examples
```bash
# Analyze a single Java file locally
java -cp "$CLASSPATH" scanner ./src/main/java/MyClass.java --local --output analysis.json

# Analyze and upload to API
java -cp "$CLASSPATH" scanner_test test/ --endpoint http://localhost:8080/api/scan

# Analyze with custom endpoint
java -cp "$CLASSPATH" scanner ./MyApp.java --endpoint https://myapi.com/scan
```

### ⚡ Analyzer Usage

The analyzer performs taint analysis on code graphs to detect vulnerabilities.

```bash
java -cp "$CLASSPATH" analyse [options]
```

#### Analyzer Options
| Option | Description | Default |
|--------|-------------|---------|
| `--api` | Fetch code graph from API instead of local file | Use local file |
| `--endpoint <url>` | Custom API endpoint URL | `http://localhost:8080/api/graph` |
| `--input <path>` | Input code graph file path | `codegraph.json` |
| `--output <path>` | Output results file path | `taint_analysis.json` |
| `--scanId <id>` | Scan ID when using API mode | Required with `--api` |

#### Examples
```bash
# Analyze local code graph
java -cp "$CLASSPATH" analyse --input codegraph.json --output vulnerabilities.json

# Analyze from API
java -cp "$CLASSPATH" analyse_test --api --endpoint http://localhost:8080/api/graph --scanId <scan-id> --output taint_analysis_api.json

# Custom analysis
java -cp "$CLASSPATH" analyse --input custom_graph.json --output custom_results.json
```

### 🌐 API Gateway Usage

Start the Spring Boot API service:

```bash
cd api-gateway
./mvnw spring-boot:run
```

The API will be available at: `http://localhost:8080`

## 🔌 API Reference

### Endpoints

| Method | Endpoint | Description | Parameters |
|--------|----------|-------------|------------|
| `POST` | `/api/scan` | Upload a code graph | `file` (multipart) |
| `GET` | `/api/graph` | Retrieve stored code graph | `scanId` (query) |
| `GET` | `/api/cfg` | Get Control Flow Graph | `scanId` (query) |
| `GET` | `/api/dfg` | Get Data Flow Graph | `scanId` (query) |
| `GET` | `/api/ast` | Get Abstract Syntax Tree | `scanId` (query) |

### Authentication

The API uses HTTP Basic Authentication:
- **Username**: `user` (configurable via `API_USER` env var)
- **Password**: `secret` (configurable via `API_PASSWORD` env var)

### Example API Usage

```bash
# Upload code graph
curl -X POST -F "file=@codegraph.json" -u user:secret http://localhost:8080/api/scan

# Retrieve analysis results
curl -u user:secret "http://localhost:8080/api/graph?scanId=your-scan-id"

# Get specific graph types
curl -u user:secret "http://localhost:8080/api/cfg?scanId=your-scan-id"
curl -u user:secret "http://localhost:8080/api/dfg?scanId=your-scan-id"
curl -u user:secret "http://localhost:8080/api/ast?scanId=your-scan-id"
```

## ⚙️ Configuration

### API Gateway Configuration

Configure the API Gateway via `api-gateway/src/main/resources/application.properties`:

```properties
# Server configuration
server.port=8080

# File upload limits
spring.servlet.multipart.max-file-size=10MB
spring.servlet.multipart.max-request-size=10MB

# Security settings
management.endpoints.web.exposure.include=*
logging.level.com.example.api_gateway=DEBUG

# Custom settings
app.upload.dir=/tmp/j-sentinel/uploads
app.output.dir=/tmp/j-sentinel/outputs
```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `API_USER` | API authentication username | `user` |
| `API_PASSWORD` | API authentication password | `secret` |
| `CLASSPATH` | Java classpath for dependencies | See installation |

## 📊 Examples

### Sample Analysis Workflow

1. **Prepare test file:**
   ```bash
   # Use the provided test file with intentional vulnerabilities
   ls test/test.java
   ```

2. **Run complete analysis:**
   ```bash
   # Step 1: Scan the code
   java -cp "$CLASSPATH" scanner test/test.java --local --output sample_graph.json
   
   # Step 2: Analyze for vulnerabilities
   java -cp "$CLASSPATH" analyse --input sample_graph.json --output sample_results.json
   
   # Step 3: View results
   cat sample_results.json
   ```

3. **API-based workflow:**
   ```bash
   # Start API server (in separate terminal)
   cd api-gateway && ./mvnw spring-boot:run
   
   # Upload and analyze
   java -cp "$CLASSPATH" scanner_test test/ --endpoint http://localhost:8080/api/scan
   # Note the returned scanId
   java -cp "$CLASSPATH" analyse_test --api --endpoint http://localhost:8080/api/graph --scanId <scan-id> --output api_results.json
   ```

### Sample Output Files

The repository includes comprehensive examples:

| File | Description |
|------|-------------|
| `test/test.java` | Sample Java file with intentional vulnerabilities |
| `codegraph.json` | Generated code graph for the sample |
| `taint_analysis.json` | Complete vulnerability analysis results |

## 📁 Project Structure

```
arjun4522-j-sentinel/
├── 🔍 scanner.java              # Core scanner implementation
├── ⚡ analyse.java              # Main analyzer implementation
├── 🧪 scanner_test.java         # Scanner test suite
├── 🧪 analyse_test.java         # Analyzer test suite
├── 📦 api-gateway.zip           # Packaged API service
├── 📊 codegraph.json           # Generated code graph output
├── 🐍 graph.py                 # Visualization script
├── 📈 taint_analysis.json      # Analysis results
├── 🌐 api-gateway/             # Spring Boot API service
│   ├── 📋 pom.xml
│   ├── 📁 src/main/java/com/example/api_gateway/
│   │   ├── 🚀 ApiGatewayApplication.java
│   │   ├── ⚙️ config/SecurityConfig.java
│   │   ├── 🎮 controller/GraphController.java
│   │   └── 💾 service/GraphStorageService.java
│   ├── 📁 src/main/resources/application.properties
│   └── 🧪 src/test/java/...
├── 📚 docs/                    # Documentation
├── 📦 lib/                     # Dependencies
└── 🧪 test/
    └── test.java               # Sample test file
```

## 📦 Dependencies

### Core Libraries

```xml
<dependencies>
    <!-- Java Parser for AST generation -->
    <dependency>
        <groupId>com.github.javaparser</groupId>
        <artifactId>javaparser-core</artifactId>
        <version>3.26.2</version>
    </dependency>
    
    <!-- Graph data structures -->
    <dependency>
        <groupId>org.jgrapht</groupId>
        <artifactId>jgrapht-core</artifactId>
        <version>1.5.2</version>
    </dependency>
    
    <!-- JSON processing -->
    <dependency>
        <groupId>org.json</groupId>
        <artifactId>json</artifactId>
        <version>20240303</version>
    </dependency>
    
    <!-- Spring Boot for API -->
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-web</artifactId>
        <version>3.x</version>
    </dependency>
</dependencies>
```

### Python Dependencies (for visualization)

```bash
pip install networkx matplotlib numpy
```

## 🔧 Troubleshooting

### Common Issues

1. **ClassPath Issues:**
   ```bash
   # Ensure all JAR files are in the classpath
   echo $CLASSPATH
   # Update paths according to your Maven repository location
   ```

2. **Permission Errors:**
   ```bash
   # Ensure temp directories have proper permissions
   chmod -R 777 /tmp/j-sentinel
   ```

3. **API Connection Issues:**
   ```bash
   # Check if API server is running
   curl -u user:secret http://localhost:8080/actuator/health
   ```

4. **Memory Issues:**
   ```bash
   # Increase JVM heap size for large codebases
   java -Xmx2g -cp "$CLASSPATH" scanner large_project/
   ```

