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

print_step "1. Installing system dependencies..."

# Update package list
apt-get update -qq

# Install required packages
apt-get install -y \
    curl \
    wget \
    git \
    build-essential \
    nodejs \
    npm \
    golang-go \
    systemd \
    ufw \
    htop \
    net-tools \
    lsof

print_status "System dependencies installed successfully"

print_step "2. Setting up Go environment..."

# Set Go environment variables
export GOPATH=/usr/local/go
export PATH=$PATH:/usr/local/go/bin
echo 'export GOPATH=/usr/local/go' >> /etc/environment
echo 'export PATH=$PATH:/usr/local/go/bin' >> /etc/environment

# Initialize Go module if not exists
if [ ! -f "go.mod" ]; then
    print_warning "go.mod not found, initializing Go module..."
    go mod init network-monitor
fi

# Download Go dependencies
print_status "Downloading Go dependencies..."
go mod tidy
go mod download

print_status "Go environment configured successfully"

print_step "3. Setting up Node.js environment..."

# Install Node.js dependencies
if [ -f "package.json" ]; then
    print_status "Installing Node.js dependencies..."
    npm install --silent
    
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

print_step "4. Building Go application..."

# Build the Go application
print_status "Compiling Go application..."
go build -o network-monitor *.go

if [ -f "network-monitor" ]; then
    print_status "Go application built successfully"
    chmod +x network-monitor
else
    print_error "Go build failed"
    exit 1
fi

print_step "5. Creating systemd service..."

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

# Security settings
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=$SCRIPT_DIR

[Install]
WantedBy=multi-user.target
EOF

print_status "Systemd service created"

print_step "6. Configuring firewall..."

# Configure UFW firewall
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh
ufw allow 8080/tcp
ufw --force enable

print_status "Firewall configured (port 8080 opened)"

print_step "7. Starting services..."

# Reload systemd and start service
systemctl daemon-reload
systemctl enable network-monitor
systemctl stop network-monitor 2>/dev/null || true
sleep 2
systemctl start network-monitor

# Wait for service to start
sleep 5

print_step "8. Verifying installation..."

# Check service status
if systemctl is-active --quiet network-monitor; then
    print_status "✅ Network Monitor service is running"
else
    print_error "❌ Network Monitor service failed to start"
    print_error "Check logs with: sudo journalctl -u network-monitor -f"
    exit 1
fi

# Test API endpoints
print_status "Testing API endpoints..."

# Wait a bit more for the server to fully initialize
sleep 3

# Test system info endpoint
if curl -s -f http://localhost:8080/api/system/info > /dev/null; then
    print_status "✅ API endpoint /api/system/info is responding"
else
    print_warning "⚠️ API endpoint /api/system/info is not responding yet"
fi

# Test WebSocket endpoint (basic check)
if curl -s -f -H "Connection: Upgrade" -H "Upgrade: websocket" http://localhost:8080/ws > /dev/null 2>&1; then
    print_status "✅ WebSocket endpoint is accessible"
else
    print_status "ℹ️ WebSocket endpoint check completed (expected behavior)"
fi

print_step "9. Final system check..."

# Display service status
echo ""
echo "=== SERVICE STATUS ==="
systemctl status network-monitor --no-pager -l

echo ""
echo "=== RECENT LOGS ==="
journalctl -u network-monitor --no-pager -n 10

echo ""
echo "=== NETWORK STATUS ==="
ss -tlnp | grep :8080 || echo "Port 8080 not found in listening ports"

echo ""
print_status "🎉 Network Monitoring System setup completed successfully!"
echo ""
echo "=== ACCESS INFORMATION ==="
echo "🌐 Web Interface: http://localhost:8080"
echo "🌐 Web Interface (external): http://$(hostname -I | awk '{print $1}'):8080"
echo "📡 WebSocket URL: ws://localhost:8080/ws"
echo "📊 API Base URL: http://localhost:8080/api"
echo ""
echo "=== MANAGEMENT COMMANDS ==="
echo "📊 Check status: sudo systemctl status network-monitor"
echo "📋 View logs: sudo journalctl -u network-monitor -f"
echo "🔄 Restart service: sudo systemctl restart network-monitor"
echo "⏹️ Stop service: sudo systemctl stop network-monitor"
echo "▶️ Start service: sudo systemctl start network-monitor"
echo ""
echo "=== FIREWALL STATUS ==="
ufw status
echo ""

# Create a simple status check script
cat > check-status.sh << 'EOF'
#!/bin/bash
echo "=== Network Monitor Status Check ==="
echo "Service Status:"
systemctl is-active network-monitor && echo "✅ Service is running" || echo "❌ Service is not running"
echo ""
echo "API Test:"
curl -s http://localhost:8080/api/system/info > /dev/null && echo "✅ API is responding" || echo "❌ API is not responding"
echo ""
echo "Port Status:"
ss -tlnp | grep :8080 && echo "✅ Port 8080 is listening" || echo "❌ Port 8080 is not listening"
echo ""
echo "Recent Logs:"
journalctl -u network-monitor --no-pager -n 5
EOF

chmod +x check-status.sh

print_status "✅ Status check script created: ./check-status.sh"
print_status "🚀 Setup completed! The system is ready to use."

exit 0
