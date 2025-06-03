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
- [Troubleshooting](#-troubleshooting)

## 🎯 Overview

J-Sentinel is a powerful static analysis tool designed to enhance application security by detecting vulnerabilities in Java code through advanced code graph analysis. It combines multiple analysis techniques to provide comprehensive security insights for Java applications, including taint analysis, control flow graphs (CFG), data flow graphs (DFG), and abstract syntax tree (AST) extraction.

## 🏗️ Architecture

J-Sentinel consists of three main components:

### Core Components
- **🔍 Scanner**: Parses Java source code and constructs detailed code graphs.
- **⚡ Analyzer**: Performs sophisticated taint analysis for vulnerability detection.
- **🌐 API Gateway**: Spring Boot service for storing and serving analysis results.

### Analysis Engines
- **🌳 Code Graph Generator**: Creates interconnected representations of code elements.
- **🔄 Control Flow Analyzer**: Tracks program execution paths.
- **📈 Data Flow Analyzer**: Analyzes data movement and transformations.
- **🌲 AST Parser**: Provides structural code representation (optional).

## ✨ Features

### 📊 Code Analysis Capabilities
- **Code Graph Generation**: Represents code elements as interconnected nodes and edges.
- **Control Flow Graph (CFG)**: Tracks program execution paths.
- **Data Flow Graph (DFG)**: Analyzes data movement and transformations.
- **Abstract Syntax Tree (AST)**: Provides structural code representation (optional).
- **Taint Analysis**: Identifies potential vulnerabilities through data flow tracking.

### 🔐 Security Vulnerability Detection
- **Log Injection Vulnerabilities**: Detects unsafe logging practices.
- **Missing Input Validations**: Identifies unvalidated user inputs.
- **Inefficient List Operations**: Spots performance bottlenecks.
- **Sensitive Data Exposures**: Finds potential data leaks.
- **Overly Broad Exception Catches**: Identifies poor error handling.

## 📦 Installation

### Prerequisites

Ensure you have the following installed:
- ☕ **Java 17+** - Main runtime environment.
- 🔧 **Maven 3.6+** - Build and dependency management for API Gateway.
- 🐍 **Python 3.8+** - For visualization capabilities (optional).

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
   Replace `/home/arjun/` with your actual Maven repository and project paths.

3. **Create required directories for API Gateway:**
   ```bash
   mkdir -p /tmp/j-sentinel/uploads /tmp/j-sentinel/outputs
   chmod -R 777 /tmp/j-sentinel
   ```

4. **Copy dependencies to `lib/` (if not already present):**
   ```bash
   mkdir -p lib
   cp ~/.m2/repository/com/github/javaparser/javaparser-core/3.26.2/javaparser-core-3.26.2.jar lib/
   cp ~/.m2/repository/org/json/json/20240303/json-20240303.jar lib/
   cp ~/.m2/repository/org/jgrapht/jgrapht-core/1.5.2/jgrapht-core-1.5.2.jar lib/
   cp ~/.m2/repository/org/jheaps/jheaps/0.14/jheaps-0.14.jar lib/
   cp ~/.m2/repository/org/apfloat/apfloat/1.10.1/apfloat-1.10.1.jar lib/
   ```

5. **Compile Java components:**
   ```bash
   javac -cp "lib/*" scanner.java analyse_test.java cfg_extract.java dfg_extract.java
   ```

6. **Start the API Gateway (for API mode):**
   ```bash
   cd api-gateway
   ./mvnw spring-boot:run
   ```

## 🚀 Usage

J-Sentinel provides a CLI agent (`jsentinel.sh`) for streamlined code analysis. The CLI supports both local mode (using JSON files) and API mode (interacting with the API Gateway).

### CLI Reference

Run the CLI from the project root:
```bash
./jsentinel.sh <subcommand> [options]
```

#### Subcommands
| Subcommand | Description |
|------------|-------------|
| `scan`     | Scan Java source code and generate a code graph. |
| `cfg`      | Extract Control Flow Graph (CFG) from the last scan. |
| `dfg`      | Extract Data Flow Graph (DFG) from the last scan. |
| `taint`    | Perform taint analysis to detect vulnerabilities. |

#### Options
| Option | Description | Default |
|--------|-------------|---------|
| `--input <path>` | Input directory or file for scanning | `test/` |
| `--output <file>` | Output JSON file path | `output/<subcommand>.json` |
| `--endpoint <url>` | API Gateway endpoint | `http://localhost:8080/api` |
| `--user <username>` | API username | `user` |
| `--password <pass>` | API password | `secret` |
| `--local` | Run in local mode (no API) | API mode |
| `--help` | Show help message | - |

### Direct Java Usage (Advanced)

For advanced users, you can run the Java components directly, though the CLI is recommended.

#### Scanner
```bash
java -cp "lib/*:." scanner <path-to-java-source> [--local] [--output <path>] [--endpoint <url>]
```

#### Analyzer
```bash
java -cp "lib/*:." analyse_test [--local <graph-path>] [--output <path>] [--endpoint <url>] [--scanId <id>]
```

#### CFG/DFG Extractors
```bash
java -cp "lib/*:." cfg_extract [--local <graph-path>] [--output <path>] [--endpoint <url>] [--scanId <id>]
java -cp "lib/*:." dfg_extract [--local <graph-path>] [--output <path>] [--endpoint <url>] [--scanId <id>]
```

**Note**: The CLI handles `scanId` automatically, making direct usage less common.

### API Gateway
The API Gateway runs at `http://localhost:8080` and handles code graph storage and analysis requests.

## 🔌 API Reference

### Endpoints

| Method | Endpoint | Description | Parameters |
|--------|----------|-------------|------------|
| `POST` | `/api/scan` | Upload a code graph | `file` (multipart) |
| `GET` | `/api/graph` | Retrieve stored code graph | `scanId` (query) |
| `GET` | `/api/cfg_extract` | Get Control Flow Graph | `scanId` (query) |
| `GET` | `/api/dfg_extract` | Get Data Flow Graph | `scanId` (query) |
| `GET` | `/api/taint_analyse` | Get taint analysis results | `scanId` (query) |
| `GET` | `/api/ast` | Get Abstract Syntax Tree | `scanId` (query) |
| `GET` | `/api/health` | Check API health | - |

### Authentication
Uses HTTP Basic Authentication:
- **Username**: `user` (or `API_USER` env var)
- **Password**: `secret` (or `API_PASSWORD` env var)

### Example API Usage
```bash
# Upload code graph
curl -X POST -F "file=@output/codegraph.json" -u user:secret http://localhost:8080/api/scan

# Retrieve code graph
curl -u user:secret "http://localhost:8080/api/graph?scanId=<scanId>"

# Get analysis results
curl -u user:secret "http://localhost:8080/api/cfg_extract?scanId=<scanId>" -o output/cfg.json
curl -u user:secret "http://localhost:8080/api/dfg_extract?scanId=<scanId>" -o output/dfg.json
curl -u user:secret "http://localhost:8080/api/taint_analyse?scanId=<scanId>" -o output/taint_analysis.json
curl -u user:secret "http://localhost:8080/api/ast?scanId=<scanId>" -o output/ast.json
```

## ⚙️ Configuration

### API Gateway Configuration
Edit `api-gateway/src/main/resources/application.properties`:
```properties
server.port=8080
spring.servlet.multipart.max-file-size=10MB
spring.servlet.multipart.max-request-size=10MB
management.endpoints.web.exposure.include=*
logging.level.com.example.api_gateway=DEBUG
app.upload.dir=/tmp/j-sentinel/uploads
app.output.dir=/tmp/j-sentinel/outputs
```

### Environment Variables
| Variable | Description | Default |
|----------|-------------|---------|
| `API_USER` | API authentication username | `user` |
| `API_PASSWORD` | API authentication password | `secret` |
| `CLASSPATH` | Java classpath for dependencies | See setup |

## 📊 Examples

### CLI Workflow (Recommended)

1. **API Mode**:
   ```bash
   # Start API Gateway (in separate terminal)
   cd api-gateway && ./mvnw spring-boot:run
   
   # Scan and upload code graph
   ./jsentinel.sh scan --input test/ --endpoint http://localhost:8080/api --user user --password secret --output output/codegraph.json
   
   # Extract CFG
   ./jsentinel.sh cfg --endpoint http://localhost:8080/api --user user --password secret --output output/cfg.json
   
   # Extract DFG
   ./jsentinel.sh dfg --endpoint http://localhost:8080/api --user user --password secret --output output/dfg.json
   
   # Perform taint analysis
   ./jsentinel.sh taint --endpoint http://localhost:8080/api --user user --password secret --output output/taint_analysis.json
   ```

2. **View Results**:
   ```bash
   ls -l output/
   head -n 10 output/taint_analysis.json
   ```

### Sample Output Files
| File | Description |
|------|-------------|
| `output/codegraph.json` | Generated code graph. |
| `output/cfg.json` | Control Flow Graph. |
| `output/dfg.json` | Data Flow Graph. |
| `output/taint_analysis.json` | Taint analysis results (~3 tainted paths for `test/`). |

## 📈 Visualization

Generate visual representations of code graphs using the provided Python script:
```bash
pip install networkx matplotlib numpy
python graph.py output/codegraph.json
```

## 📁 Project Structure

```
j-sentinel/
├── 🔍 scanner.java              # Core scanner implementation
├── ⚡ analyse_test.java         # Taint analyzer implementation
├── 📈 cfg_extract.java         # CFG extractor
├── 📈 dfg_extract.java         # DFG extractor
├── 🌲 ast_extract.java         # AST extractor (optional)
├── 📜 jsentinel.sh             # CLI agent
├── 📦 api-gateway/             # Spring Boot API service
│   ├── 📋 pom.xml
│   ├── 📁 src/main/java/com/example/api_gateway/
│   │   ├── 🚀 ApiGatewayApplication.java
│   │   ├── ⚙️ config/SecurityConfig.java
│   │   ├── 🎮 controller/GraphController.java
│   │   └── 💾 service/GraphStorageService.java
│   ├── 📁 src/main/resources/application.properties
│   └── 🧪 src/test/java/...
├── 📦 lib/                     # Dependencies (JARs)
├── 📁 output/                  # Analysis results
├── 🧪 test/                    # Sample test files
│   └── test.java
└── 🐍 graph.py                 # Visualization script
```

## 📦 Dependencies

### Core Libraries
```xml
<dependencies>
    <dependency>
        <groupId>com.github.javaparser</groupId>
        <artifactId>javaparser-core</artifactId>
        <version>3.26.2</version>
    </dependency>
    <dependency>
        <groupId>org.jgrapht</groupId>
        <artifactId>jgrapht-core</artifactId>
        <version>1.5.2</version>
    </dependency>
    <dependency>
        <groupId>org.json</groupId>
        <artifactId>json</artifactId>
        <version>20240303</version>
    </dependency>
    <dependency>
        <groupId>org.jheaps</groupId>
        <artifactId>jheaps</artifactId>
        <version>0.14</version>
    </dependency>
    <dependency>
        <groupId>org.apfloat</groupId>
        <artifactId>apfloat</artifactId>
        <version>1.10.1</version>
    </dependency>
</dependencies>
```

### API Gateway
See `api-gateway/pom.xml` for Spring Boot dependencies.

### Python (Visualization)
```bash
pip install networkx matplotlib numpy
```

## 🔧 Troubleshooting

1. **Classpath Issues**:
   ```bash
   echo $CLASSPATH
   # Ensure all JARs are in lib/
   ls -l lib/
   ```

2. **Permission Errors**:
   ```bash
   chmod -R 777 /tmp/j-sentinel
   ```

3. **API Connection Issues**:
   ```bash
   curl -u user:secret http://localhost:8080/api/health
   ```

4. **Java Compilation Errors**:
   ```bash
   javac -cp "lib/*" scanner.java
   ```

5. **Missing scanId**:
   ```bash
   cat .jsentinel_scanid
   # Ensure scan was run first
   ```
