#!/bin/bash

echo "🔍 天眼监控系统状态检查"
echo "======================"

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

# 检查进程状态
echo "📊 进程状态:"
if pgrep -f "sky-eye-monitor-real" > /dev/null; then
    echo "✅ 监控系统正在运行"
    echo "   进程ID: $(pgrep -f "sky-eye-monitor-real")"
    echo "   运行时间: $(ps -o etime= -p $(pgrep -f "sky-eye-monitor-real"))"
else
    echo "❌ 监控系统未运行"
fi

echo ""

# 检查端口监听
echo "🔌 端口状态:"
if netstat -tlnp 2>/dev/null | grep :8080 > /dev/null; then
    echo "✅ 端口8080正在监听"
    netstat -tlnp | grep :8080
else
    echo "❌ 端口8080未监听"
fi

echo ""

# 检查API响应
echo "📡 API状态:"
if curl -s -f --connect-timeout 5 http://localhost:8080/api/system/info > /dev/null; then
    echo "✅ API响应正常"
else
    echo "❌ API无响应"
fi

echo ""

# 检查WebSocket
echo "🔗 WebSocket状态:"
if command -v wscat &> /dev/null; then
    if timeout 3 wscat -c ws://localhost:8080/ws > /dev/null 2>&1; then
        echo "✅ WebSocket连接正常"
    else
        echo "❌ WebSocket连接失败"
    fi
else
    echo "ℹ️ 未安装wscat，无法测试WebSocket"
fi

echo ""

# 显示最近日志
echo "📋 最近日志 (最后10行):"
if [ -f "logs/monitor.log" ]; then
    tail -10 logs/monitor.log
else
    echo "❌ 未找到日志文件"
fi

echo ""

# 显示系统资源使用
echo "💻 系统资源:"
echo "   CPU使用率: $(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | cut -d'%' -f1)%"
echo "   内存使用: $(free | grep Mem | awk '{printf "%.1f%%", $3/$2 * 100.0}')"
echo "   磁盘使用: $(df / | tail -1 | awk '{print $5}')"

echo ""
echo "🔧 管理命令:"
echo "   重启服务: sudo ./deploy.sh"
echo "   查看日志: tail -f logs/monitor.log"
echo "   停止服务: pkill -f sky-eye-monitor-real"
