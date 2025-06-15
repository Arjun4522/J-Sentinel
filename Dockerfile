# Multi-stage Dockerfile for J-Sentinel
FROM ubuntu:22.04 as builder

# Set environment variables
ENV DEBIAN_FRONTEND=noninteractive
ENV JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64
ENV GOPATH=/go
ENV PATH=$PATH:/usr/local/go/bin:$GOPATH/bin

# Install system dependencies
RUN apt-get update && apt-get install -y \
    openjdk-17-jdk \
    maven \
    python3 \
    python3-pip \
    wget \
    curl \
    git \
    sqlite3 \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install Go
RUN wget https://go.dev/dl/go1.21.0.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go1.21.0.linux-amd64.tar.gz && \
    rm go1.21.0.linux-amd64.tar.gz

# Set working directory
WORKDIR /app

# Copy project files
COPY . .

# Install Python dependencies
RUN pip3 install --no-cache-dir semgrep pyyaml requests

# Create required directories
RUN mkdir -p /tmp/j-sentinel/uploads /tmp/j-sentinel/outputs && \
    chmod -R 777 /tmp/j-sentinel && \
    mkdir -p reports

# Build rule engine binary
WORKDIR /app/rule-engine
RUN chmod +x build.sh && ./build.sh

# Build Spring Boot API Gateway
WORKDIR /app/api-gateway
RUN ./mvnw clean install -DskipTests

# Set up database
WORKDIR /app
RUN go run initdb.go db_setup.go

# Production stage
FROM ubuntu:22.04

# Set environment variables
ENV DEBIAN_FRONTEND=noninteractive
ENV JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64
ENV API_USER=user
ENV API_PASSWORD=secret
ENV SPRING_PROFILES_ACTIVE=docker

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    openjdk-17-jre-headless \
    python3 \
    python3-pip \
    sqlite3 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
RUN pip3 install --no-cache-dir semgrep pyyaml requests

# Create app user for security
RUN useradd -m -u 1000 jsentinel && \
    mkdir -p /app /tmp/j-sentinel/uploads /tmp/j-sentinel/outputs && \
    chown -R jsentinel:jsentinel /app /tmp/j-sentinel

# Set working directory
WORKDIR /app

# Copy built artifacts from builder stage
COPY --from=builder --chown=jsentinel:jsentinel /app/rule-engine/detect ./rule-engine/detect
COPY --from=builder --chown=jsentinel:jsentinel /app/rule-engine/rules ./rule-engine/rules
COPY --from=builder --chown=jsentinel:jsentinel /app/rule-engine/detect_test.py ./rule-engine/detect_test.py
COPY --from=builder --chown=jsentinel:jsentinel /app/api-gateway/target/*.jar ./api-gateway/app.jar
COPY --from=builder --chown=jsentinel:jsentinel /app/reports ./reports
COPY --from=builder --chown=jsentinel:jsentinel /app/test ./test

# Copy configuration files
COPY --chown=jsentinel:jsentinel docker-entrypoint.sh /app/
COPY --chown=jsentinel:jsentinel api-gateway/src/main/resources/application-docker.properties /app/application-docker.properties

# Make scripts executable
RUN chmod +x /app/docker-entrypoint.sh && \
    chmod +x /app/rule-engine/detect

# Switch to app user
USER jsentinel

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f -u ${API_USER}:${API_PASSWORD} http://localhost:8080/actuator/health || exit 1

# Set entrypoint
ENTRYPOINT ["/app/docker-entrypoint.sh"]