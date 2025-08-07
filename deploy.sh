#!/bin/bash

# 天眼网络监控系统 - 完整部署脚本
# 此脚本将自动安装所有依赖并启动监控系统

set -e

echo "🚀 开始部署天眼网络监控系统"
echo "=================================="

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# 输出函数
print_status() {
    echo -e "${GREEN}[信息]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[警告]${NC} $1"
}

print_error() {
    echo -e "${RED}[错误]${NC} $1"
}

print_step() {
    echo -e "${BLUE}[步骤]${NC} $1"
}

# 检查是否为root用户
if [[ $EUID -ne 0 ]]; then
   print_error "此脚本需要root权限运行，请使用 sudo"
   echo "使用方法: sudo ./deploy.sh"
   exit 1
fi

# 获取脚本目录
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

print_step "1. 检查系统环境"

# 检测操作系统
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$NAME
    print_status "检测到操作系统: $OS"
else
    print_error "无法检测操作系统"
    exit 1
fi

print_step "2. 更新系统包管理器"

# 更新包列表
print_status "更新包列表..."
if command -v apt-get &> /dev/null; then
    apt-get update -qq
elif command -v yum &> /dev/null; then
    yum update -y -q
elif command -v dnf &> /dev/null; then
    dnf update -y -q
else
    print_error "不支持的包管理器"
    exit 1
fi

print_step "3. 安装系统依赖"

# 安装基础工具
print_status "安装基础工具..."
if command -v apt-get &> /dev/null; then
    apt-get install -y curl wget git build-essential net-tools lsof htop unzip
elif command -v yum &> /dev/null; then
    yum install -y curl wget git gcc gcc-c++ make net-tools lsof htop unzip
elif command -v dnf &> /dev/null; then
    dnf install -y curl wget git gcc gcc-c++ make net-tools lsof htop unzip
fi

print_step "4. 安装 Go 语言环境"

# 检查Go是否已安装
if command -v go &> /dev/null; then
    GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
    print_status "Go已安装，版本: $GO_VERSION"
else
    print_status "安装Go语言..."
    GO_VERSION="1.21.5"
    
    # 下载Go
    wget -q "https://golang.org/dl/go${GO_VERSION}.linux-amd64.tar.gz"
    
    # 删除旧版本并安装新版本
    rm -rf /usr/local/go
    tar -C /usr/local -xzf "go${GO_VERSION}.linux-amd64.tar.gz"
    rm "go${GO_VERSION}.linux-amd64.tar.gz"
    
    # 设置环境变量
    echo 'export PATH=$PATH:/usr/local/go/bin' >> /etc/profile
    export PATH=$PATH:/usr/local/go/bin
    
    print_status "Go ${GO_VERSION} 安装完成"
fi

print_step "5. 安装 Node.js 环境"

# 检查Node.js是否已安装
if command -v node &> /dev/null; then
    NODE_VERSION=$(node --version)
    print_status "Node.js已安装，版本: $NODE_VERSION"
    
    # 检查版本是否足够新
    NODE_MAJOR=$(echo $NODE_VERSION | cut -d'.' -f1 | sed 's/v//')
    if [ "$NODE_MAJOR" -lt 18 ]; then
        print_warning "Node.js版本过低，需要升级到18.x"
        # 卸载旧版本
        apt-get remove -y nodejs npm || true
        apt-get purge -y nodejs npm || true
        apt-get autoremove -y || true
        rm -rf /usr/local/bin/node /usr/local/bin/npm /usr/local/lib/node_modules ~/.npm ~/.node-gyp
        
        # 安装新版本
        curl -fsSL https://deb.nodesource.com/setup_18.x | bash -
        apt-get install -y nodejs
        print_status "Node.js 18.x 安装完成"
    fi
else
    print_status "安装Node.js..."
    
    # 安装NodeSource仓库
    curl -fsSL https://deb.nodesource.com/setup_18.x | bash -
    
    if command -v apt-get &> /dev/null; then
        apt-get install -y nodejs
    elif command -v yum &> /dev/null; then
        yum install -y nodejs npm
    elif command -v dnf &> /dev/null; then
        dnf install -y nodejs npm
    fi
    
    print_status "Node.js 安装完成"
fi

print_step "6. 配置Go项目环境"

# 设置Go环境变量
export GOPATH=/usr/local/go
export PATH=$PATH:/usr/local/go/bin

# 初始化Go模块
if [ ! -f "go.mod" ]; then
    print_status "初始化Go模块..."
    /usr/local/go/bin/go mod init network-monitor
fi

# 清理go.sum避免版本冲突
rm -f go.sum

# 下载Go依赖
print_status "下载Go依赖包..."
/usr/local/go/bin/go mod tidy
/usr/local/go/bin/go mod download

print_step "7. 构建前端应用"

# 检查package.json是否存在
if [ -f "package.json" ]; then
    print_status "清理现有依赖..."
    rm -rf node_modules package-lock.json
    
    print_status "安装Node.js依赖..."
    npm install --silent --no-audit --no-fund
    
    print_status "构建React前端..."
    npm run build
    
    if [ -d "out" ]; then
        print_status "前端构建成功"
    else
        print_error "前端构建失败"
        exit 1
    fi
else
    print_warning "未找到package.json，跳过前端构建"
fi

print_step "8. 编译Go后端程序"

print_status "编译Go应用程序..."
/usr/local/go/bin/go build -o network-monitor *.go

if [ -f "network-monitor" ]; then
    chmod +x network-monitor
    print_status "Go程序编译成功"
else
    print_error "Go程序编译失败"
    exit 1
fi

print_step "9. 配置防火墙"

print_status "配置防火墙规则..."

# 配置iptables或ufw
if command -v ufw &> /dev/null; then
    ufw --force reset >/dev/null 2>&1
    ufw default deny incoming >/dev/null 2>&1
    ufw default allow outgoing >/dev/null 2>&1
    ufw allow ssh >/dev/null 2>&1
    ufw allow 8080/tcp >/dev/null 2>&1
    ufw --force enable >/dev/null 2>&1
    print_status "UFW防火墙配置完成"
elif command -v firewall-cmd &> /dev/null; then
    firewall-cmd --permanent --add-port=8080/tcp >/dev/null 2>&1
    firewall-cmd --reload >/dev/null 2>&1
    print_status "firewalld防火墙配置完成"
else
    print_warning "未找到防火墙工具，请手动开放8080端口"
fi

print_step "10. 启动监控系统"

# 停止现有进程
print_status "停止现有进程..."
pkill -f network-monitor || true
sleep 2

# 启动新进程
print_status "启动天眼监控系统..."
nohup ./network-monitor > monitor.log 2>&1 &
MONITOR_PID=$!

# 等待启动
sleep 5

print_step "11. 验证部署结果"

# 检查进程是否运行
if kill -0 $MONITOR_PID 2>/dev/null; then
    print_status "✅ 监控系统启动成功 (PID: $MONITOR_PID)"
    
    # 测试API端点
    sleep 3
    if curl -s -f --connect-timeout 10 http://localhost:8080/api/system/info > /dev/null; then
        print_status "✅ API端点响应正常"
    else
        print_warning "⚠️ API端点暂未响应，请稍后再试"
    fi
    
    # 获取IP地址
    LOCAL_IP=$(hostname -I | awk '{print $1}')
    
    echo ""
    echo "🎉 部署完成！"
    echo "=================================="
    echo ""
    echo "📊 访问地址:"
    echo "   本地访问: http://localhost:8080"
    echo "   局域网访问: http://${LOCAL_IP}:8080"
    echo ""
    echo "🔧 管理命令:"
    echo "   查看状态: ps aux | grep network-monitor"
    echo "   查看日志: tail -f monitor.log"
    echo "   停止服务: pkill -f network-monitor"
    echo "   重启服务: sudo ./deploy.sh"
    echo ""
    echo "📋 系统信息:"
    echo "   进程ID: $MONITOR_PID"
    echo "   日志文件: $SCRIPT_DIR/monitor.log"
    echo "   工作目录: $SCRIPT_DIR"
    echo ""
    
    # 显示防火墙状态
    if command -v ufw &> /dev/null; then
        echo "🔥 防火墙状态:"
        ufw status
    fi
    
else
    print_error "❌ 监控系统启动失败"
    
    if [ -f "monitor.log" ]; then
        echo ""
        echo "错误日志:"
        echo "----------"
        tail -20 monitor.log
    fi
    
    exit 1
fi

print_status "🚀 天眼网络监控系统部署完成！"
