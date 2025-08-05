#!/bin/bash

echo "🔧 启用真实数据收集..."

# 检查权限
if [ "$EUID" -ne 0 ]; then
    echo "❌ 请使用root权限运行此脚本"
    echo "使用: sudo bash enable-real-data.sh"
    exit 1
fi

# 设置Go环境
export PATH=$PATH:/usr/local/go/bin
export GOPATH=$HOME/go
export PATH=$PATH:$GOPATH/bin

echo "✅ Go环境已设置"

# 停止现有服务
echo "🛑 停止现有服务..."
pkill -f "sky-eye-monitor" 2>/dev/null || true

# 编译新版本
echo "🔨 编译真实数据版本..."
go build -o sky-eye-monitor-real *.go

if [ $? -ne 0 ]; then
    echo "❌ 编译失败"
    exit 1
fi

echo "✅ 编译成功"

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

# 启动真实数据监控
echo "🚀 启动天眼监控系统 (真实数据模式)..."
nohup ./sky-eye-monitor-real > logs/monitor.log 2>&1 &

echo "✅ 服务已启动"
echo "📊 访问地址: http://$(hostname -I | awk '{print $1}'):8080"
echo "📋 查看日志: tail -f logs/monitor.log"
EOF

chmod +x start-real-monitor.sh

# 创建停止脚本
cat > stop-real-monitor.sh << 'EOF'
#!/bin/bash

echo "🛑 停止天眼监控系统..."
pkill -f "sky-eye-monitor-real"

if [ $? -eq 0 ]; then
    echo "✅ 服务已停止"
else
    echo "⚠️ 没有找到运行中的服务"
fi
EOF

chmod +x stop-real-monitor.sh

# 创建状态检查脚本
cat > status-real-monitor.sh << 'EOF'
#!/bin/bash

echo "📊 天眼监控系统状态检查..."

# 检查进程
if pgrep -f "sky-eye-monitor-real" > /dev/null; then
    echo "✅ 服务运行中"
    echo "🔍 进程ID: $(pgrep -f 'sky-eye-monitor-real')"
    echo "💾 内存使用: $(ps -o pid,vsz,rss,comm -p $(pgrep -f 'sky-eye-monitor-real') | tail -1)"
else
    echo "❌ 服务未运行"
fi

# 检查端口
if netstat -tuln | grep -q ":8080 "; then
    echo "✅ 端口8080已监听"
else
    echo "❌ 端口8080未监听"
fi

# 检查日志文件
if [ -f "logs/monitor.log" ]; then
    echo "📋 最新日志:"
    tail -5 logs/monitor.log
else
    echo "⚠️ 日志文件不存在"
fi

echo ""
echo "🌐 访问地址: http://$(hostname -I | awk '{print $1}'):8080"
EOF

chmod +x status-real-monitor.sh

echo ""
echo "🎉 真实数据收集器配置完成!"
echo ""
echo "📋 可用命令:"
echo "  启动服务: ./start-real-monitor.sh"
echo "  停止服务: ./stop-real-monitor.sh"
echo "  查看状态: ./status-real-monitor.sh"
echo ""
echo "🔍 真实数据源:"
echo "  ✓ 系统网络流量统计"
echo "  ✓ 真实服务器状态检测"
echo "  ✓ 日志文件监控 (nginx/apache/syslog)"
echo "  ✓ 系统资源使用情况"
echo "  ✓ 进程监控"
echo "  ✓ 安全事件检测"
echo ""

# 询问是否立即启动
read -p "是否立即启动服务? (y/n): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    ./start-real-monitor.sh
    sleep 2
    ./status-real-monitor.sh
fi

echo ""
echo "✅ 真实数据监控系统已就绪!"
