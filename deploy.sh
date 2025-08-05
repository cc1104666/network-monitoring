#!/bin/bash

echo "🚀 开始部署天眼网络监控系统..."

# 检查并安装Go环境
install_go() {
    echo "📦 正在安装Go语言环境..."
    
    # 检测系统类型
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS=$NAME
        VER=$VERSION_ID
    elif type lsb_release >/dev/null 2>&1; then
        OS=$(lsb_release -si)
        VER=$(lsb_release -sr)
    elif [[ -f /etc/redhat-release ]]; then
        OS="CentOS"
        VER=$(rpm -q --qf "%{VERSION}" $(rpm -q --whatprovides redhat-release))
    else
        OS=$(uname -s)
        VER=$(uname -r)
    fi
    
    echo "检测到系统: $OS $VER"
    
    # 根据系统类型安装Go
    case "$OS" in
        *"Ubuntu"*|*"Debian"*)
            echo "使用apt安装Go..."
            sudo apt-get update
            sudo apt-get install -y wget curl
            
            # 下载并安装最新版Go
            GO_VERSION="1.21.5"
            wget -q https://golang.org/dl/go${GO_VERSION}.linux-amd64.tar.gz -O /tmp/go.tar.gz
            
            if [ $? -eq 0 ]; then
                sudo rm -rf /usr/local/go
                sudo tar -C /usr/local -xzf /tmp/go.tar.gz
                rm /tmp/go.tar.gz
                
                # 设置环境变量
                echo 'export PATH=$PATH:/usr/local/go/bin' | sudo tee -a /etc/profile
                echo 'export GOPATH=$HOME/go' | sudo tee -a /etc/profile
                echo 'export PATH=$PATH:$GOPATH/bin' | sudo tee -a /etc/profile
                
                # 为当前会话设置环境变量
                export PATH=$PATH:/usr/local/go/bin
                export GOPATH=$HOME/go
                export PATH=$PATH:$GOPATH/bin
                
                echo "✅ Go安装成功"
            else
                echo "❌ Go下载失败，尝试使用包管理器安装..."
                sudo apt-get install -y golang-go
            fi
            ;;
            
        *"CentOS"*|*"Red Hat"*|*"Rocky"*|*"AlmaLinux"*)
            echo "使用yum/dnf安装Go..."
            
            # 检查是否有dnf
            if command -v dnf &> /dev/null; then
                PKG_MANAGER="dnf"
            else
                PKG_MANAGER="yum"
            fi
            
            sudo $PKG_MANAGER update -y
            sudo $PKG_MANAGER install -y wget curl
            
            # 下载并安装最新版Go
            GO_VERSION="1.21.5"
            wget -q https://golang.org/dl/go${GO_VERSION}.linux-amd64.tar.gz -O /tmp/go.tar.gz
            
            if [ $? -eq 0 ]; then
                sudo rm -rf /usr/local/go
                sudo tar -C /usr/local -xzf /tmp/go.tar.gz
                rm /tmp/go.tar.gz
                
                # 设置环境变量
                echo 'export PATH=$PATH:/usr/local/go/bin' | sudo tee -a /etc/profile
                echo 'export GOPATH=$HOME/go' | sudo tee -a /etc/profile
                echo 'export PATH=$PATH:$GOPATH/bin' | sudo tee -a /etc/profile
                
                # 为当前会话设置环境变量
                export PATH=$PATH:/usr/local/go/bin
                export GOPATH=$HOME/go
                export PATH=$PATH:$GOPATH/bin
                
                echo "✅ Go安装成功"
            else
                echo "❌ Go下载失败，尝试使用包管理器安装..."
                sudo $PKG_MANAGER install -y golang
            fi
            ;;
            
        *"Amazon Linux"*)
            echo "使用yum安装Go (Amazon Linux)..."
            sudo yum update -y
            sudo yum install -y wget curl
            
            # Amazon Linux通常使用较新的Go版本
            GO_VERSION="1.21.5"
            wget -q https://golang.org/dl/go${GO_VERSION}.linux-amd64.tar.gz -O /tmp/go.tar.gz
            
            if [ $? -eq 0 ]; then
                sudo rm -rf /usr/local/go
                sudo tar -C /usr/local -xzf /tmp/go.tar.gz
                rm /tmp/go.tar.gz
                
                # 设置环境变量
                echo 'export PATH=$PATH:/usr/local/go/bin' | sudo tee -a /etc/profile
                echo 'export GOPATH=$HOME/go' | sudo tee -a /etc/profile
                echo 'export PATH=$PATH:$GOPATH/bin' | sudo tee -a /etc/profile
                
                # 为当前会话设置环境变量
                export PATH=$PATH:/usr/local/go/bin
                export GOPATH=$HOME/go
                export PATH=$PATH:$GOPATH/bin
                
                echo "✅ Go安装成功"
            else
                echo "❌ Go下载失败"
                return 1
            fi
            ;;
            
        *)
            echo "⚠️ 未识别的系统类型: $OS"
            echo "请手动安装Go语言环境: https://golang.org/dl/"
            return 1
            ;;
    esac
    
    # 验证安装
    if command -v go &> /dev/null; then
        echo "✅ Go安装验证成功: $(go version)"
        return 0
    else
        echo "❌ Go安装失败，请手动安装"
        return 1
    fi
}

# 检查系统环境
check_requirements() {
    echo "📋 检查系统环境..."
    
    # 检查是否为root用户或有sudo权限
    if [[ $EUID -ne 0 ]] && ! sudo -n true 2>/dev/null; then
        echo "❌ 需要root权限或sudo权限来安装依赖"
        echo "请使用: sudo $0 或切换到root用户"
        exit 1
    fi
    
    # 检查Go环境
    if ! command -v go &> /dev/null; then
        echo "⚠️ 未找到Go语言环境，正在自动安装..."
        if ! install_go; then
            echo "❌ Go安装失败，请手动安装后重试"
            echo "官方下载地址: https://golang.org/dl/"
            exit 1
        fi
    else
        echo "✅ Go版本: $(go version)"
        
        # 检查Go版本是否足够新
        GO_VERSION=$(go version | grep -oP 'go\K[0-9]+\.[0-9]+' | head -1)
        REQUIRED_VERSION="1.19"
        
        if [ "$(printf '%s\n' "$REQUIRED_VERSION" "$GO_VERSION" | sort -V | head -n1)" != "$REQUIRED_VERSION" ]; then
            echo "⚠️ Go版本过低 ($GO_VERSION)，建议升级到 $REQUIRED_VERSION 或更高版本"
            read -p "是否继续安装？(y/n): " -n 1 -r
            echo
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                exit 1
            fi
        fi
    fi
    
    # 检查网络连接
    echo "🌐 检查网络连接..."
    if ! curl -s --connect-timeout 5 https://golang.org > /dev/null; then
        echo "⚠️ 网络连接可能有问题，但继续安装..."
    else
        echo "✅ 网络连接正常"
    fi
    
    # 检查端口占用
    if command -v lsof &> /dev/null && lsof -Pi :8080 -sTCP:LISTEN -t >/dev/null 2>&1; then
        echo "⚠️ 端口8080已被占用"
        echo "占用进程: $(lsof -Pi :8080 -sTCP:LISTEN 2>/dev/null | tail -n +2 || echo '无法获取进程信息')"
        read -p "是否继续部署？(y/n): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
    
    # 检查磁盘空间
    AVAILABLE_SPACE=$(df . | tail -1 | awk '{print $4}')
    REQUIRED_SPACE=1048576  # 1GB in KB
    
    if [ "$AVAILABLE_SPACE" -lt "$REQUIRED_SPACE" ]; then
        echo "⚠️ 磁盘空间不足，建议至少有1GB可用空间"
        echo "当前可用空间: $(($AVAILABLE_SPACE / 1024))MB"
        read -p "是否继续？(y/n): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
}

# 安装系统依赖
install_system_dependencies() {
    echo "📦 安装系统依赖..."
    
    # 检测系统类型并安装必要工具
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS=$NAME
    fi
    
    case "$OS" in
        *"Ubuntu"*|*"Debian"*)
            sudo apt-get update
            sudo apt-get install -y curl wget git build-essential lsof
            ;;
        *"CentOS"*|*"Red Hat"*|*"Rocky"*|*"AlmaLinux"*)
            if command -v dnf &> /dev/null; then
                sudo dnf install -y curl wget git gcc make lsof
            else
                sudo yum install -y curl wget git gcc make lsof
            fi
            ;;
        *"Amazon Linux"*)
            sudo yum install -y curl wget git gcc make lsof
            ;;
    esac
    
    echo "✅ 系统依赖安装完成"
}

# 创建项目结构
setup_project() {
    echo "📁 创建项目结构..."
    
    # 创建必要目录
    mkdir -p {static,config,logs,data}
    
    # 设置目录权限
    chmod 755 {static,config,logs,data}
    
    # 创建配置文件
    cat > config/config.yaml << EOF
server:
  port: 8080
  host: "0.0.0.0"
  
monitoring:
  update_interval: 3s
  data_retention: 1000
  
agents:
  - name: "本地服务器"
    host: "localhost"
    port: 8080
    type: "local"
  - name: "Web服务器-1"
    host: "192.168.1.10"
    port: 8080
    type: "remote"
  - name: "API服务器-1" 
    host: "192.168.1.20"
    port: 8080
    type: "remote"
  - name: "数据库服务器"
    host: "192.168.1.30"
    port: 8080
    type: "remote"

threats:
  rate_limit_threshold: 1000
  brute_force_threshold: 50
  ddos_threshold: 10000
EOF

    echo "✅ 项目结构创建完成"
}

# 安装Go依赖
install_dependencies() {
    echo "📦 安装Go依赖..."
    
    # 设置Go代理（加速下载）
    export GOPROXY=https://goproxy.cn,direct
    export GOSUMDB=sum.golang.google.cn
    
    # 清理现有依赖
    rm -f go.sum go.mod
    
    # 重新初始化模块
    go mod init network-monitor
    
    # 添加依赖
    echo "📥 添加必要依赖..."
    
    # 使用超时和重试机制
    for i in {1..3}; do
        echo "尝试第 $i 次下载依赖..."
        
        if go get github.com/gorilla/mux@v1.8.1 && \
           go get github.com/gorilla/websocket@v1.5.1 && \
           go get github.com/shirou/gopsutil/v3@v3.23.10; then
            echo "✅ 依赖下载成功"
            break
        else
            echo "❌ 依赖下载失败，重试中..."
            if [ $i -eq 3 ]; then
                echo "❌ 多次尝试后依赖下载仍然失败"
                echo "请检查网络连接或手动执行："
                echo "go get github.com/gorilla/mux@v1.8.1"
                echo "go get github.com/gorilla/websocket@v1.5.1"
                echo "go get github.com/shirou/gopsutil/v3@v3.23.10"
                exit 1
            fi
            sleep 5
        fi
    done
    
    # 整理依赖
    go mod tidy
    
    # 下载依赖
    go mod download
    
    echo "✅ 依赖安装完成"
}

# 编译程序
build_application() {
    echo "🔨 编译应用程序..."
    
    # 设置编译参数
    export CGO_ENABLED=1
    export GOOS=linux
    
    # 编译主程序
    go build -ldflags="-s -w" -o sky-eye-monitor *.go
    
    if [ $? -eq 0 ]; then
        echo "✅ 编译成功"
        # 设置执行权限
        chmod +x sky-eye-monitor
        
        # 显示文件信息
        echo "📊 程序信息:"
        ls -lh sky-eye-monitor
    else
        echo "❌ 编译失败"
        echo "请检查Go版本和代码是否正确"
        echo "错误日志已保存，可以查看详细信息"
        exit 1
    fi
}

# 创建系统服务
create_service() {
    echo "🔧 创建系统服务..."
    
    # 获取当前目录
    CURRENT_DIR=$(pwd)
    CURRENT_USER=$(whoami)
    
    # 创建systemd服务文件
    sudo tee /etc/systemd/system/sky-eye-monitor.service > /dev/null << EOF
[Unit]
Description=Sky Eye Network Monitor
Documentation=https://github.com/your-repo/sky-eye-monitor
After=network.target
Wants=network.target

[Service]
Type=simple
User=$CURRENT_USER
Group=$CURRENT_USER
WorkingDirectory=$CURRENT_DIR
ExecStart=$CURRENT_DIR/sky-eye-monitor
ExecReload=/bin/kill -HUP \$MAINPID
Restart=always
RestartSec=10
StandardOutput=append:$CURRENT_DIR/logs/monitor.log
StandardError=append:$CURRENT_DIR/logs/error.log
SyslogIdentifier=sky-eye-monitor

# 安全设置
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=$CURRENT_DIR

# 资源限制
LimitNOFILE=65536
LimitNPROC=4096

[Install]
WantedBy=multi-user.target
EOF

    # 重新加载systemd
    sudo systemctl daemon-reload
    
    echo "✅ 系统服务创建完成"
}

# 配置防火墙
configure_firewall() {
    echo "🔥 配置防火墙..."
    
    # 检查并配置ufw
    if command -v ufw &> /dev/null; then
        echo "配置ufw防火墙..."
        sudo ufw allow 8080/tcp comment "Sky Eye Monitor"
        echo "✅ ufw防火墙配置完成"
    fi
    
    # 检查并配置firewalld
    if command -v firewall-cmd &> /dev/null && sudo systemctl is-active firewalld &> /dev/null; then
        echo "配置firewalld防火墙..."
        sudo firewall-cmd --permanent --add-port=8080/tcp
        sudo firewall-cmd --reload
        echo "✅ firewalld防火墙配置完成"
    fi
    
    # 检查并配置iptables
    if command -v iptables &> /dev/null && ! command -v ufw &> /dev/null && ! command -v firewall-cmd &> /dev/null; then
        echo "配置iptables防火墙..."
        sudo iptables -A INPUT -p tcp --dport 8080 -j ACCEPT
        # 尝试保存iptables规则
        if command -v iptables-save &> /dev/null; then
            sudo iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
        fi
        echo "✅ iptables防火墙配置完成"
    fi
}

# 启动服务
start_service() {
    echo "🚀 启动监控服务..."
    
    # 创建日志目录
    mkdir -p logs
    chmod 755 logs
    
    # 启动服务
    sudo systemctl enable sky-eye-monitor
    sudo systemctl start sky-eye-monitor
    
    # 等待服务启动
    echo "⏳ 等待服务启动..."
    sleep 5
    
    # 检查服务状态
    if sudo systemctl is-active --quiet sky-eye-monitor; then
        echo "✅ 服务启动成功"
        
        # 获取服务器IP
        LOCAL_IP=$(hostname -I | awk '{print $1}')
        EXTERNAL_IP=$(curl -s --connect-timeout 5 ifconfig.me 2>/dev/null || curl -s --connect-timeout 5 ipinfo.io/ip 2>/dev/null || echo "YOUR_SERVER_IP")
        
        echo ""
        echo "🎉 天眼监控系统启动成功！"
        echo "📊 本地访问: http://localhost:8080"
        echo "📊 内网访问: http://$LOCAL_IP:8080"
        echo "📊 外网访问: http://$EXTERNAL_IP:8080"
        echo ""
        echo "📋 服务管理命令:"
        echo "  查看状态: sudo systemctl status sky-eye-monitor"
        echo "  查看日志: sudo journalctl -u sky-eye-monitor -f"
        echo "  重启服务: sudo systemctl restart sky-eye-monitor"
        echo "  停止服务: sudo systemctl stop sky-eye-monitor"
        
    else
        echo "❌ 服务启动失败"
        echo "查看错误日志:"
        echo "  sudo journalctl -u sky-eye-monitor --no-pager"
        echo "  cat logs/error.log"
        echo ""
        echo "尝试手动启动测试:"
        echo "  ./sky-eye-monitor"
        exit 1
    fi
}

# 手动启动选项
manual_start() {
    echo "🚀 手动启动服务..."
    
    # 创建日志目录
    mkdir -p logs
    chmod 755 logs
    
    echo "启动命令选项:"
    echo "1. 前台运行: ./sky-eye-monitor"
    echo "2. 后台运行: nohup ./sky-eye-monitor > logs/monitor.log 2>&1 &"
    echo "3. 使用screen: screen -S sky-eye -dm ./sky-eye-monitor"
    echo ""
    
    read -p "是否现在启动服务？(y/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo "后台启动服务..."
        nohup ./sky-eye-monitor > logs/monitor.log 2>&1 &
        
        sleep 3
        
        if pgrep -f sky-eye-monitor > /dev/null; then
            echo "✅ 服务启动成功！"
            
            # 获取服务器IP
            LOCAL_IP=$(hostname -I | awk '{print $1}')
            EXTERNAL_IP=$(curl -s --connect-timeout 5 ifconfig.me 2>/dev/null || echo "YOUR_SERVER_IP")
            
            echo "📊 访问地址: http://$EXTERNAL_IP:8080"
            echo "📝 查看日志: tail -f logs/monitor.log"
            echo "🛑 停止服务: pkill -f sky-eye-monitor"
        else
            echo "❌ 服务启动失败，查看日志: cat logs/monitor.log"
        fi
    fi
}

# 显示部署信息
show_info() {
    echo ""
    echo "🎉 天眼监控系统部署完成！"
    echo ""
    echo "📁 重要文件:"
    echo "  程序文件: $(pwd)/sky-eye-monitor"
    echo "  配置文件: $(pwd)/config/config.yaml"
    echo "  日志目录: $(pwd)/logs/"
    echo "  数据目录: $(pwd)/data/"
    echo ""
    echo "🤖 部署监控代理:"
    echo "  1. 在其他服务器上创建目录: mkdir -p /opt/sky-eye-agent"
    echo "  2. 复制程序文件到代理服务器"
    echo "  3. 设置环境变量并启动代理模式"
    echo ""
    echo "📚 更多信息:"
    echo "  项目文档: README.md"
    echo "  配置说明: config/config.yaml"
    echo "  故障排除: 查看logs目录下的日志文件"
    echo ""
}

# 清理函数
cleanup() {
    echo ""
    echo "🧹 清理临时文件..."
    rm -f /tmp/go.tar.gz
}

# 设置信号处理
trap cleanup EXIT

# 主执行流程
main() {
    echo "开始时间: $(date)"
    echo "安装目录: $(pwd)"
    echo "执行用户: $(whoami)"
    echo ""
    
    check_requirements
    install_system_dependencies
    setup_project
    install_dependencies
    build_application
    
    # 询问是否创建系统服务
    echo ""
    read -p "是否创建系统服务并自动启动(推荐)？(y/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        create_service
        configure_firewall
        start_service
    else
        manual_start
    fi
    
    show_info
    
    echo ""
    echo "部署完成时间: $(date)"
}

# 执行主函数
main "$@"
