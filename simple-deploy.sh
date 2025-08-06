#!/bin/bash

# 天眼监控系统 - 快速部署
# This script provides a streamlined deployment process

set -e

echo "🚀 天眼监控系统 - 快速部署"
echo "========================="

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
    echo "❌ 请使用 sudo 运行此脚本"
    echo "使用方法: sudo ./simple-deploy.sh"
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
    rm go1.21.5.linux-amd64.tar.gz
    export PATH=$PATH:/usr/local/go/bin
    echo 'export PATH=$PATH:/usr/local/go/bin' >> /etc/profile
    print_status "Go installed successfully"
else
    print_status "Go found: $(go version)"
fi

# Check for Node.js
if ! command -v node &> /dev/null; then
    print_warning "Node.js not found, installing..."
    curl -fsSL https://deb.nodesource.com/setup_18.x | bash -
    apt-get install -y nodejs npm
    print_status "Node.js installed successfully"
else
    print_status "Node.js found: $(node --version)"
fi

print_step "2. Installing dependencies..."

# Install system packages
apt-get update -qq
apt-get install -y curl wget git build-essential nodejs npm

print_step "3. Building application..."

# Initialize Go module
if [ ! -f "go.mod" ]; then
    go mod init network-monitor
fi

# Download Go dependencies
go mod tidy

# Build Go application
go build -o network-monitor *.go
chmod +x network-monitor

# Build frontend
if [ -f "package.json" ]; then
    npm install --silent
    npm run build
    print_status "Frontend built successfully"
fi

print_step "4. Configuring firewall..."

# Configure firewall
if command -v ufw &> /dev/null; then
    ufw allow 8080/tcp >/dev/null 2>&1
    print_status "Firewall configured to allow port 8080"
else
    print_warning "ufw not found, skipping firewall configuration"
fi

print_step "5. Starting service..."

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
    LOCAL_IP=$(hostname -I | awk '{print $1}')
    print_status "✅ Network Monitor started successfully (PID: $MONITOR_PID)"
    
    # Test API endpoint
    if curl -s -f http://localhost:8080/api/system/info > /dev/null; then
        print_status "✅ API endpoint is responding"
    else
        print_warning "⚠️ API endpoint not responding yet"
    fi
    
    echo ""
    echo "✅ 部署成功！"
    echo "🌐 访问地址: http://localhost:8080"
    echo "🌐 局域网访问: http://${LOCAL_IP}:8080"
    echo "📋 查看日志: tail -f monitor.log"
    echo "🛑 停止服务: pkill -f network-monitor"
    echo ""
else
    print_error "❌ 部署失败，查看日志: cat monitor.log"
    exit 1
fi

print_status "🎉 Deployment completed successfully!"
