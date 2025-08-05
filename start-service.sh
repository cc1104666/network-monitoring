#!/bin/bash

echo "🚀 启动天眼监控系统..."

# 检查程序是否存在
if [ ! -f "./sky-eye-monitor" ]; then
    echo "❌ 未找到程序文件，请先编译"
    echo "运行: bash fix-go-env.sh"
    exit 1
fi

# 检查是否已经在运行
if pgrep -f sky-eye-monitor > /dev/null; then
    echo "⚠️ 服务已在运行中"
    echo "PID: $(pgrep -f sky-eye-monitor)"
    
    read -p "是否重启服务？(y/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo "🛑 停止现有服务..."
        pkill -f sky-eye-monitor
        sleep 2
    else
        echo "服务继续运行"
        exit 0
    fi
fi

# 创建日志目录
mkdir -p logs

# 启动服务
echo "🚀 启动服务..."
nohup ./sky-eye-monitor > logs/monitor.log 2>&1 &

# 等待启动
sleep 3

# 检查启动状态
if pgrep -f sky-eye-monitor > /dev/null; then
    echo "✅ 服务启动成功！"
    
    # 获取服务器IP信息
    LOCAL_IP=$(hostname -I | awk '{print $1}')
    EXTERNAL_IP=$(curl -s --connect-timeout 5 ifconfig.me 2>/dev/null || curl -s --connect-timeout 5 ipinfo.io/ip 2>/dev/null || echo "YOUR_SERVER_IP")
    
    echo ""
    echo "🎉 天眼监控系统运行中！"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "📊 访问地址:"
    echo "   本地访问: http://localhost:8080"
    echo "   内网访问: http://$LOCAL_IP:8080"
    echo "   外网访问: http://$EXTERNAL_IP:8080"
    echo ""
    echo "🔧 管理命令:"
    echo "   查看状态: ps aux | grep sky-eye-monitor"
    echo "   查看日志: tail -f logs/monitor.log"
    echo "   实时日志: tail -f logs/monitor.log | grep -E '(ERROR|WARN|INFO)'"
    echo "   停止服务: pkill -f sky-eye-monitor"
    echo "   重启服务: bash start-service.sh"
    echo ""
    echo "📝 日志文件:"
    echo "   主日志: logs/monitor.log"
    echo "   错误日志: logs/error.log"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    # 显示最新日志
    echo ""
    echo "📋 最新日志 (最近10行):"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    tail -n 10 logs/monitor.log 2>/dev/null || echo "暂无日志"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
else
    echo "❌ 服务启动失败"
    echo ""
    echo "🔍 故障排除:"
    echo "1. 查看错误日志: cat logs/monitor.log"
    echo "2. 检查端口占用: lsof -i :8080"
    echo "3. 手动启动测试: ./sky-eye-monitor"
    echo "4. 检查权限: ls -la sky-eye-monitor"
    echo ""
    echo "📋 错误日志:"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    cat logs/monitor.log 2>/dev/null || echo "无法读取日志文件"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    exit 1
fi
