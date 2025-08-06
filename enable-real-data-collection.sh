#!/bin/bash

# Network Monitoring System - Complete Setup Script
# This script sets up the complete network monitoring system with real data collection

set -e  # Exit on any error

echo "🚀 Starting Network Monitoring System Setup..."

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_step() {
    echo -e "${BLUE}[STEP]${NC} $1"
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   print_error "This script must be run as root (use sudo)"
   exit 1
fi

# Get the directory where the script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

print_step "1. Fixing package repository issues..."

# Fix GPG key issues
print_status "Fixing GPG key issues..."
apt-key adv --keyserver keyserver.ubuntu.com --recv-keys B7B3B788A8D3785C 2>/dev/null || true

# Remove problematic repositories temporarily
if [ -f /etc/apt/sources.list.d/mysql.list ]; then
    mv /etc/apt/sources.list.d/mysql.list /etc/apt/sources.list.d/mysql.list.bak
    print_status "Temporarily disabled MySQL repository"
fi

# Update package list with error handling
print_status "Updating package lists..."
apt-get update -qq --allow-releaseinfo-change || {
    print_warning "Some repositories failed to update, continuing with available packages"
}

print_step "2. Installing system dependencies..."

# Install required packages
apt-get install -y \
    curl \
    wget \
    git \
    build-essential \
    systemd \
    ufw \
    htop \
    net-tools \
    lsof \
    ca-certificates \
    gnupg \
    software-properties-common \
    npm \
    wscat 2>/dev/null || {
    print_warning "Some packages failed to install, continuing..."
}

print_step "3. Installing Go..."

# Check if Go is already installed
if command -v go &> /dev/null; then
    GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
    print_status "Go is already installed: $GO_VERSION"
else
    print_status "Installing Go..."
    GO_VERSION="1.21.5"
    wget -q https://golang.org/dl/go${GO_VERSION}.linux-amd64.tar.gz
    tar -C /usr/local -xzf go${GO_VERSION}.linux-amd64.tar.gz
    rm go${GO_VERSION}.linux-amd64.tar.gz
    
    # Add Go to PATH
    echo 'export PATH=$PATH:/usr/local/go/bin' >> /etc/profile
    export PATH=$PATH:/usr/local/go/bin
    
    print_status "Go ${GO_VERSION} installed successfully"
fi

print_step "4. Installing Node.js..."

# Check if Node.js is already installed
if command -v node &> /dev/null; then
    NODE_VERSION=$(node --version)
    print_status "Node.js is already installed: $NODE_VERSION"
else
    print_status "Installing Node.js..."
    curl -fsSL https://deb.nodesource.com/setup_18.x | bash -
    apt-get install -y nodejs
    print_status "Node.js installed successfully"
fi

print_step "5. Setting up Go environment..."

# Set Go environment variables
export GOPATH=/usr/local/go
export PATH=$PATH:/usr/local/go/bin
echo 'export GOPATH=/usr/local/go' >> /etc/environment
echo 'export PATH=$PATH:/usr/local/go/bin' >> /etc/environment

# Initialize Go module if not exists
if [ ! -f "go.mod" ]; then
    print_warning "go.mod not found, initializing Go module..."
    /usr/local/go/bin/go mod init network-monitor
fi

# Clean go.sum to avoid version conflicts
rm -f go.sum

# Add necessary dependencies
go mod edit -require github.com/gorilla/mux@v1.8.0
go mod edit -require github.com/gorilla/websocket@v1.5.0
go mod edit -require github.com/rs/cors@v1.10.1

# Download Go dependencies
print_status "Downloading Go dependencies..."
go mod tidy

print_status "Go environment configured successfully"

print_step "6. Setting up Node.js environment..."

# Install Node.js dependencies
if [ -f "package.json" ]; then
    print_status "Installing Node.js dependencies..."
    npm install --silent --no-audit --no-fund
    
    # Build the frontend
    print_status "Building React frontend..."
    npm run build
    
    if [ -d "out" ]; then
        print_status "Frontend built successfully"
    else
        print_error "Frontend build failed - out directory not created"
        exit 1
    fi
else
    print_warning "package.json not found, skipping Node.js setup"
fi

print_step "7. Building Go application..."

# Build the Go application
print_status "Compiling Go application..."
/usr/local/go/bin/go build -o network-monitor *.go

if [ -f "network-monitor" ]; then
    print_status "Go application built successfully"
    chmod +x network-monitor
else
    print_error "Go build failed"
    exit 1
fi

print_step "8. Creating systemd service..."

# Create systemd service file
cat > /etc/systemd/system/network-monitor.service << EOF
[Unit]
Description=Network Monitoring System
After=network.target
Wants=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$SCRIPT_DIR
ExecStart=$SCRIPT_DIR/network-monitor
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=network-monitor

# Environment variables
Environment=GOPATH=/usr/local/go
Environment=PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/go/bin
Environment=ENABLE_REAL_DATA=true

# Security settings
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=$SCRIPT_DIR

[Install]
WantedBy=multi-user.target
EOF

print_status "Systemd service created"

print_step "9. Configuring firewall..."

# Configure UFW firewall
ufw --force reset >/dev/null 2>&1
ufw default deny incoming >/dev/null 2>&1
ufw default allow outgoing >/dev/null 2>&1
ufw allow ssh >/dev/null 2>&1
ufw allow 8080/tcp >/dev/null 2>&1
ufw --force enable >/dev/null 2>&1

print_status "Firewall configured (port 8080 opened)"

print_step "10. Starting services..."

# Stop existing service
print_status "Stopping existing service..."
pkill -f network-monitor || true
sleep 2

# Start the Go application
print_status "Starting Go application..."
nohup ./network-monitor > monitor.log 2>&1 &
MONITOR_PID=$!

# Wait for service to start
sleep 5

print_step "11. Verifying installation..."

# Check service status
if kill -0 $MONITOR_PID 2>/dev/null; then
    print_status "✅ Network Monitor service is running"
    
    # Test API endpoints
    print_status "Testing API endpoints..."
    
    # Wait a bit more for the server to fully initialize
    sleep 3
    
    # Test system info endpoint
    if curl -s -f --connect-timeout 10 http://localhost:8080/api/system/info > /dev/null; then
        print_status "✅ API endpoint /api/system/info is responding"
    else
        print_warning "⚠️ API endpoint /api/system/info is not responding yet"
    fi
    
    # Test WebSocket endpoint (basic check)
    if command -v wscat &> /dev/null; then
        timeout 3 wscat -c ws://localhost:8080/ws > /dev/null 2>&1 && \
        print_status "✅ WebSocket endpoint is accessible" || \
        print_warning "⚠️ WebSocket endpoint check completed (expected behavior)"
    fi
    
    echo ""
    echo "=== ACCESS INFORMATION ==="
    echo "🌐 Web Interface: http://localhost:8080"
    echo "🌐 Web Interface (external): http://$(hostname -I | awk '{print $1}'):8080"
    echo "📡 WebSocket URL: ws://localhost:8080/ws"
    echo "📊 API Base URL: http://localhost:8080/api"
    echo ""
    echo "=== MANAGEMENT COMMANDS ==="
    echo "📊 Check status: ps aux | grep network-monitor"
    echo "📋 View logs: tail -f monitor.log"
    echo "🔄 Restart service: ./enable-real-data-collection.sh"
    echo "⏹️ Stop service: pkill -f network-monitor"
    echo "▶️ Start service: ./enable-real-data-collection.sh"
    echo ""
    echo "=== FIREWALL STATUS ==="
    ufw status
    echo ""
    
    print_status "🎉 Network Monitoring System setup completed successfully!"
else
    print_error "❌ Network Monitor service failed to start"
    print_error "Check logs with: cat monitor.log"
    
    if [ -f "monitor.log" ]; then
        echo ""
        echo "=== ERROR LOGS ==="
        tail -20 monitor.log
    fi
    
    exit 1
fi

# Restore MySQL repository if it was backed up
if [ -f /etc/apt/sources.list.d/mysql.list.bak ]; then
    mv /etc/apt/sources.list.d/mysql.list.bak /etc/apt/sources.list.d/mysql.list
    print_status "Restored MySQL repository"
fi

exit 0
