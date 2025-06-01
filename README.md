# 🛡️ J-Sentinel: Java Code Analysis Tool

🔍 A comprehensive Java static code analysis tool that performs taint analysis and vulnerability detection through detailed code graph construction.

## 📋 Overview

J-Sentinel is a powerful static analysis tool designed to enhance Java application security by detecting vulnerabilities through advanced code graph analysis. It combines multiple analysis techniques to provide comprehensive security insights.

### 🏗️ Architecture Components

- **🔍 Scanner**: Parses Java source code and constructs detailed code graphs
- **⚡ Analyzer**: Performs sophisticated taint analysis for vulnerability detection  
- **🌐 API Gateway**: Spring Boot service for storing and serving analysis results

## ✨ Features

### 📊 Code Analysis Capabilities
- 🌳 **Code Graph Generation**: Represents code elements as interconnected nodes and edges
- 🔄 **Control Flow Graph (CFG)**: Tracks program execution paths
- 📈 **Data Flow Graph (DFG)**: Analyzes data movement and transformations
- 🌲 **Abstract Syntax Tree (AST)**: Provides structural code representation

### 🔐 Security Vulnerability Detection
- 📝 **Log Injection Vulnerabilities**: Detects unsafe logging practices
- ✅ **Missing Input Validations**: Identifies unvalidated user inputs
- ⚡ **Inefficient List Operations**: Spots performance bottlenecks
- 🔒 **Sensitive Data Exposures**: Finds potential data leaks
- 🎯 **Overly Broad Exception Catches**: Identifies poor error handling

## 📁 Project Structure

```
└── arjun4522-j-sentinel/
    ├── 🔍 analyse.java              # Main analyzer implementation
    ├── 🧪 analyse_test.java         # Analyzer test suite
    ├── 📦 api-gateway.zip           # Packaged API service
    ├── 📊 codegraph.json           # Generated code graph output
    ├── 🐍 graph.py                 # Visualization script
    ├── 🔎 scanner.java             # Core scanner implementation
    ├── 🧪 scanner_test.java        # Scanner test suite
    ├── 📈 taint_analysis.json      # Analysis results
    ├── 🌐 api-gateway/             # Spring Boot API service
    │   ├── 📋 pom.xml
    │   ├── 📁 src/
    │   │   ├── 📁 main/java/com/example/api_gateway/
    │   │   │   ├── 🚀 ApiGatewayApplication.java
    │   │   │   ├── ⚙️ config/SecurityConfig.java
    │   │   │   ├── 🎮 controller/GraphController.java
    │   │   │   └── 💾 service/GraphStorageService.java
    │   │   └── 📁 resources/application.properties
    │   └── 🧪 test/java/...
    ├── 📚 docs/                    # Documentation
    ├── 📦 lib/                     # Dependencies
    └── 🧪 test/
        └── test.java               # Sample test file
```

## 🚀 Getting Started

### 📋 Prerequisites

- ☕ **Java 17+** - Main runtime environment
- 🔧 **Maven** - Build and dependency management
- 🐍 **Python 3.x** - For visualization capabilities

### 🔍 Running the Scanner

```bash
java scanner.java <path-to-java-source> [options]
```

#### 🛠️ Scanner Options
| Option | Description |
|--------|-------------|
| `--local` | 💾 Save output locally instead of uploading to API |
| `--output <path>` | 📄 Specify output file path |
| `--endpoint <url>` | 🌐 Custom API endpoint URL |

**Example:**
```bash
java scanner.java ./src/main/java/MyClass.java --local --output analysis.json
```

### ⚡ Running the Analyzer

```bash
java analyse.java [options]
```

#### 🛠️ Analyzer Options
| Option | Description |
|--------|-------------|
| `--api` | 🌐 Fetch code graph from API instead of local file |
| `--endpoint <url>` | 🔗 Custom API endpoint URL |
| `--input <path>` | 📁 Input code graph file path |
| `--output <path>` | 📊 Output results file path |

**Example:**
```bash
java analyse.java --input codegraph.json --output vulnerabilities.json
```

### 🌐 Running the API Gateway

```bash
cd api-gateway
./mvnw spring-boot:run
```

🌍 **API will be available at:** `http://localhost:8080`

## 🔌 API Endpoints

| Method | Endpoint | Description | 📝 |
|--------|----------|-------------|-----|
| `POST` | `/api/scan` | Upload a code graph | 📤 |
| `GET` | `/api/graph` | Retrieve stored code graph by scanId | 📊 |
| `GET` | `/api/cfg` | Get Control Flow Graph for a scan | 🔄 |
| `GET` | `/api/dfg` | Get Data Flow Graph for a scan | 📈 |
| `GET` | `/api/ast` | Get Abstract Syntax Tree for a scan | 🌲 |

### 📋 Example API Usage

```bash
# Upload code graph
curl -X POST -F "file=@codegraph.json" http://localhost:8080/api/scan

# Retrieve analysis results
curl http://localhost:8080/api/graph?scanId=your-scan-id
```

## 📊 Visualization

Generate interactive code graph visualizations:

```bash
python graph.py
```

🎨 **Features:**
- Interactive network graphs using NetworkX
- Matplotlib-based plotting
- Customizable node and edge styling
- Export capabilities

## 📁 Sample Analysis

The repository includes comprehensive examples:

| File | Description | 🏷️ |
|------|-------------|-----|
| `test/test.java` | Sample Java file with intentional vulnerabilities | 🧪 |
| `codegraph.json` | Generated code graph for the sample | 📊 |
| `taint_analysis.json` | Complete vulnerability analysis results | 🔍 |

## ⚙️ Configuration

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
```

## 📦 Dependencies

### Core Libraries
- 🔧 **JavaParser** - Java code parsing and AST generation
- 📊 **JGraphT** - Graph data structures and algorithms
- 🌐 **Spring Boot** - RESTful API framework
- 🐍 **NetworkX** - Python graph visualization
- 📈 **Matplotlib** - Plotting and visualization

### Build Dependencies
```xml
<dependencies>
    <dependency>
        <groupId>com.github.javaparser</groupId>
        <artifactId>javaparser-core</artifactId>
        <version>3.25.1</version>
    </dependency>
    <dependency>
        <groupId>org.jgrapht</groupId>
        <artifactId>jgrapht-core</artifactId>
        <version>1.5.1</version>
    </dependency>
</dependencies>
```
