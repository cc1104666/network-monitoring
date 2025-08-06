#!/bin/bash

# Simple Network Monitoring System Deployment Script
# This script provides a streamlined deployment process

set -e

echo "🚀 Simple Network Monitoring System Deployment"
echo "=============================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

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

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

print_step "1. Checking system requirements..."

# Check for Go
if ! command -v go &> /dev/null; then
    print_warning "Go not found, installing..."
    wget -q https://golang.org/dl/go1.21.5.linux-amd64.tar.gz
    tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz
    export PATH=$PATH:/usr/local/go/bin
    echo 'export PATH=$PATH:/usr/local/go/bin' >> /etc/profile
    rm go1.21.5.linux-amd64.tar.gz
    print_status "Go installed successfully"
else
    print_status "Go found: $(go version)"
fi

# Check for Node.js
if ! command -v node &> /dev/null; then
    print_warning "Node.js not found, installing..."
    curl -fsSL https://deb.nodesource.com/setup_18.x | bash -
    apt-get install -y nodejs
    print_status "Node.js installed successfully"
else
    print_status "Node.js found: $(node --version)"
fi

print_step "2. Installing dependencies..."

# Install system packages
apt-get update -qq
apt-get install -y curl wget git build-essential net-tools lsof

# Initialize Go module
if [ ! -f "go.mod" ]; then
    /usr/local/go/bin/go mod init network-monitor
fi

# Download Go dependencies
/usr/local/go/bin/go mod tidy

# Install Node.js dependencies
if [ -f "package.json" ]; then
    npm install --silent
    npm run build
    print_status "Frontend built successfully"
fi

print_step "3. Building application..."

# Build Go application
/usr/local/go/bin/go build -o network-monitor *.go
chmod +x network-monitor

print_step "4. Starting service..."

# Kill any existing process
pkill -f network-monitor || true
sleep 2

# Start the application in background
nohup ./network-monitor > monitor.log 2>&1 &
MONITOR_PID=$!

# Wait for startup
sleep 5

# Check if process is running
if kill -0 $MONITOR_PID 2>/dev/null; then
    print_status "✅ Network Monitor started successfully (PID: $MONITOR_PID)"
    
    # Test API endpoint
    if curl -s -f http://localhost:8080/api/system/info > /dev/null; then
        print_status "✅ API endpoint is responding"
    else
        print_warning "⚠️ API endpoint not responding yet"
    fi
    
    echo ""
    echo "=== ACCESS INFORMATION ==="
    echo "🌐 Web Interface: http://localhost:8080"
    echo "🌐 External Access: http://$(hostname -I | awk '{print $1}'):8080"
    echo "📊 API Base: http://localhost:8080/api"
    echo "📋 Logs: tail -f monitor.log"
    echo ""
    echo "=== MANAGEMENT ==="
    echo "Stop: pkill -f network-monitor"
    echo "Status: ps aux | grep network-monitor"
    echo "Logs: tail -f monitor.log"
    
else
    print_error "❌ Failed to start Network Monitor"
    print_error "Check logs: cat monitor.log"
    exit 1
fi

print_status "🎉 Deployment completed successfully!"
