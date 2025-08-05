#!/bin/bash

echo "🔧 完整修复并构建天眼监控系统..."

# 检查权限
if [ "$EUID" -ne 0 ]; then
    echo "❌ 请使用root权限运行此脚本"
    echo "使用: sudo bash complete-fix-and-build.sh"
    exit 1
fi

# 设置Go环境
export PATH=$PATH:/usr/local/go/bin
export GOPATH=$HOME/go
export PATH=$PATH:$GOPATH/bin
export GOPROXY=https://goproxy.cn,direct
export GOSUMDB=sum.golang.google.cn
export GO111MODULE=on

echo "✅ Go环境已设置"

# 停止现有服务
echo "🛑 停止现有服务..."
pkill -f "sky-eye-monitor" 2>/dev/null || true

# 完全清理Go模块
echo "🧹 完全清理Go模块..."
rm -rf go.mod go.sum
go clean -cache
go clean -modcache

# 重新初始化Go模块
echo "📦 重新初始化Go模块..."
go mod init network-monitor

# 逐个添加依赖并下载
echo "📥 添加并下载依赖包..."

echo "  添加 gorilla/mux..."
go get github.com/gorilla/mux@v1.8.1
go mod download github.com/gorilla/mux

echo "  添加 gorilla/websocket..."
go get github.com/gorilla/websocket@v1.5.1
go mod download github.com/gorilla/websocket

echo "  添加 gopsutil..."
go get github.com/shirou/gopsutil/v3@v3.23.10
go mod download github.com/shirou/gopsutil/v3

# 整理依赖
echo "🔄 整理依赖..."
go mod tidy

# 验证依赖
echo "✅ 验证依赖..."
go mod verify

# 显示go.mod和go.sum状态
echo "📋 检查模块文件..."
if [ -f "go.mod" ]; then
    echo "✅ go.mod 存在"
    echo "内容预览:"
    head -10 go.mod
else
    echo "❌ go.mod 不存在"
fi

if [ -f "go.sum" ]; then
    echo "✅ go.sum 存在"
    echo "条目数量: $(wc -l < go.sum)"
else
    echo "❌ go.sum 不存在"
fi

# 编译新版本
echo "🔨 编译真实数据版本..."
go build -ldflags="-s -w" -o sky-eye-monitor-real *.go

if [ $? -ne 0 ]; then
    echo "❌ 编译失败，显示详细错误信息："
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    go build -v -o sky-eye-monitor-real *.go
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    echo ""
    echo "🛠️ 故障排除建议:"
    echo "1. 检查网络连接: curl -I https://goproxy.cn"
    echo "2. 手动下载依赖: go mod download -x"
    echo "3. 检查Go版本: go version"
    echo "4. 清理并重试: go clean -cache && go mod download"
    
    exit 1
fi

echo "✅ 编译成功"

# 设置执行权限
chmod +x sky-eye-monitor-real

# 创建必要的目录
mkdir -p logs
mkdir -p data

# 设置日志文件权限
touch logs/monitor.log
chmod 644 logs/monitor.log

# 创建启动脚本
cat > start-real-monitor.sh << 'EOF'
#!/bin/bash

# 设置环境变量
export PATH=$PATH:/usr/local/go/bin

# 检查程序文件
if [ ! -f "./sky-eye-monitor-real" ]; then
    echo "❌ 程序文件不存在，请先编译"
    exit 1
fi

# 检查是否已经运行
if pgrep -f "sky-eye-monitor-real" > /dev/null; then
    echo "⚠️ 服务已在运行中"
    echo "PID: $(pgrep -f 'sky-eye-monitor-real')"
    
    read -p "是否重启服务？(y/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo "🛑 停止现有服务..."
        pkill -f "sky-eye-monitor-real"
        sleep 2
    else
        echo "服务继续运行"
        exit 0
    fi
fi

# 启动真实数据监控
echo "🚀 启动天眼监控系统 (真实数据模式)..."
nohup ./sky-eye-monitor-real > logs/monitor.log 2>&1 &

# 等待启动
sleep 3

# 检查启动状态
if pgrep -f "sky-eye-monitor-real" > /dev/null; then
    echo "✅ 服务启动成功"
    
    # 获取服务器IP信息
    LOCAL_IP=$(hostname -I | awk '{print $1}')
    EXTERNAL_IP=$(curl -s --connect-timeout 5 ifconfig.me 2>/dev/null || echo "YOUR_SERVER_IP")
    
    echo ""
    echo "🎉 天眼监控系统运行中 (真实数据模式)！"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "📊 访问地址:"
    echo "   本地访问: http://localhost:8080"
    echo "   内网访问: http://$LOCAL_IP:8080"
    echo "   外网访问: http://$EXTERNAL_IP:8080"
    echo ""
    echo "🔍 真实数据源:"
    echo "   ✓ 系统网络流量统计"
    echo "   ✓ 真实服务器状态检测"
    echo "   ✓ 日志文件监控"
    echo "   ✓ 系统资源使用情况"
    echo "   ✓ 进程监控"
    echo "   ✓ 安全事件检测"
    echo ""
    echo "🔧 管理命令:"
    echo "   查看状态: ./status-real-monitor.sh"
    echo "   查看日志: tail -f logs/monitor.log"
    echo "   停止服务: ./stop-real-monitor.sh"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    # 显示最新日志
    echo ""
    echo "📋 最新日志 (最近5行):"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    tail -n 5 logs/monitor.log 2>/dev/null || echo "暂无日志"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
else
    echo "❌ 服务启动失败"
    echo ""
    echo "🔍 故障排除:"
    echo "1. 查看错误日志: cat logs/monitor.log"
    echo "2. 检查端口占用: lsof -i :8080"
    echo "3. 手动启动测试: ./sky-eye-monitor-real"
    echo "4. 检查权限: ls -la sky-eye-monitor-real"
    echo ""
    echo "📋 错误日志:"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    cat logs/monitor.log 2>/dev/null || echo "无法读取日志文件"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    exit 1
fi
EOF

chmod +x start-real-monitor.sh

# 创建停止脚本
cat > stop-real-monitor.sh << 'EOF'
#!/bin/bash

echo "🛑 停止天眼监控系统..."

# 查找进程
PIDS=$(pgrep -f "sky-eye-monitor-real")

if [ -z "$PIDS" ]; then
    echo "ℹ️ 服务未运行"
    exit 0
fi

echo "发现运行中的进程: $PIDS"

# 优雅停止
echo "正在停止服务..."
pkill -TERM -f "sky-eye-monitor-real"

# 等待进程结束
sleep 3

# 检查是否还在运行
if pgrep -f "sky-eye-monitor-real" > /dev/null; then
    echo "⚠️ 进程未正常结束，强制终止..."
    pkill -KILL -f "sky-eye-monitor-real"
    sleep 1
fi

# 最终检查
if pgrep -f "sky-eye-monitor-real" > /dev/null; then
    echo "❌ 无法停止服务，请手动处理"
    echo "运行: kill -9 $(pgrep -f 'sky-eye-monitor-real')"
else
    echo "✅ 服务已停止"
fi
EOF

chmod +x stop-real-monitor.sh

# 创建状态检查脚本
cat > status-real-monitor.sh << 'EOF'
#!/bin/bash

echo "📊 天眼监控系统状态检查 (真实数据模式)..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# 检查进程
PIDS=$(pgrep -f "sky-eye-monitor-real")
if [ -n "$PIDS" ]; then
    echo "✅ 服务状态: 运行中"
    echo "📋 进程信息:"
    ps aux | grep "sky-eye-monitor-real" | grep -v grep
    echo ""
    
    # 检查端口
    if lsof -i :8080 > /dev/null 2>&1; then
        echo "✅ 端口状态: 8080端口已监听"
        echo "📋 端口信息:"
        lsof -i :8080
    else
        echo "❌ 端口状态: 8080端口未监听"
    fi
    
    echo ""
    
    # 检查网络连接
    LOCAL_IP=$(hostname -I | awk '{print $1}')
    EXTERNAL_IP=$(curl -s --connect-timeout 5 ifconfig.me 2>/dev/null || echo "无法获取")
    
    echo "🌐 网络信息:"
    echo "   本地IP: $LOCAL_IP"
    echo "   外网IP: $EXTERNAL_IP"
    echo "   访问地址: http://$EXTERNAL_IP:8080"
    
    echo ""
    
    # 检查日志
    if [ -f "logs/monitor.log" ]; then
        echo "📝 最新日志 (最近5行):"
        tail -n 5 logs/monitor.log
    else
        echo "⚠️ 未找到日志文件"
    fi
    
else
    echo "❌ 服务状态: 未运行"
    
    # 检查程序文件
    if [ -f "./sky-eye-monitor-real" ]; then
        echo "✅ 程序文件: 存在"
        ls -la sky-eye-monitor-real
    else
        echo "❌ 程序文件: 不存在，需要编译"
    fi
    
    # 检查端口占用
    if lsof -i :8080 > /dev/null 2>&1; then
        echo "⚠️ 端口8080被其他进程占用:"
        lsof -i :8080
    fi
fi

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "🔧 管理命令:"
echo "   启动服务: ./start-real-monitor.sh"
echo "   停止服务: ./stop-real-monitor.sh"
echo "   查看日志: tail -f logs/monitor.log"
echo "   重新编译: sudo bash complete-fix-and-build.sh"
EOF

chmod +x status-real-monitor.sh

echo ""
echo "🎉 天眼监控系统构建完成！"
echo ""
echo "📋 可用命令:"
echo "  启动服务: ./start-real-monitor.sh"
echo "  停止服务: ./stop-real-monitor.sh"
echo "  查看状态: ./status-real-monitor.sh"
echo ""
echo "🔍 真实数据源:"
echo "  ✓ 系统网络流量统计 (/proc/net/dev)"
echo "  ✓ 真实服务器状态检测 (TCP连接测试)"
echo "  ✓ 日志文件监控 (nginx/apache/syslog)"
echo "  ✓ 系统资源使用情况 (/proc/stat, /proc/meminfo)"
echo "  ✓ 进程监控 (pgrep, ps)"
echo "  ✓ 安全事件检测 (日志分析)"
echo ""
echo "📊 程序信息:"
ls -lh sky-eye-monitor-real 2>/dev/null || echo "程序文件不存在"

# 询问是否立即启动
read -p "是否立即启动服务? (y/n): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    ./start-real-monitor.sh
else
    echo "稍后可运行 './start-real-monitor.sh' 启动服务"
fi

echo ""
echo "✅ 真实数据监控系统已就绪!"
