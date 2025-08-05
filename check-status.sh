#!/bin/bash

echo "📊 天眼监控系统状态检查..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# 检查Go环境
if command -v go &> /dev/null; then
    echo "✅ Go环境: $(go version)"
else
    echo "❌ Go环境: 未安装"
fi

# 检查程序文件
if [ -f "./sky-eye-monitor-real" ]; then
    echo "✅ 程序文件: 存在"
    ls -lh sky-eye-monitor-real
else
    echo "❌ 程序文件: 不存在"
fi

# 检查Go模块
if [ -f "go.mod" ]; then
    echo "✅ go.mod: 存在"
else
    echo "❌ go.mod: 不存在"
fi

if [ -f "go.sum" ]; then
    echo "✅ go.sum: 存在 ($(wc -l < go.sum) 条目)"
else
    echo "❌ go.sum: 不存在"
fi

# 检查进程
PIDS=$(pgrep -f "sky-eye-monitor-real")
if [ -n "$PIDS" ]; then
    echo "✅ 服务状态: 运行中 (PID: $PIDS)"
    
    # 检查端口
    if lsof -i :8080 > /dev/null 2>&1; then
        echo "✅ 端口状态: 8080端口已监听"
    else
        echo "❌ 端口状态: 8080端口未监听"
    fi
    
    # 获取访问地址
    LOCAL_IP=$(hostname -I | awk '{print $1}')
    echo "🌐 访问地址: http://$LOCAL_IP:8080"
    
else
    echo "❌ 服务状态: 未运行"
fi

# 检查日志
if [ -f "logs/monitor.log" ]; then
    echo "📝 日志文件: 存在"
    echo "最新日志:"
    tail -n 3 logs/monitor.log
else
    echo "⚠️ 日志文件: 不存在"
fi

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "🔧 可用命令:"
echo "  构建系统: bash complete-fix-go-sum.sh"
echo "  快速启动: bash quick-start-monitor.sh"
echo "  查看状态: bash check-status.sh"
echo "  停止服务: pkill -f sky-eye-monitor-real"
