#!/bin/bash

echo "📊 天眼监控系统状态检查..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# 检查进程状态
PIDS=$(pgrep -f sky-eye-monitor)
if [ -n "$PIDS" ]; then
    echo "✅ 服务状态: 运行中"
    echo "📋 进程信息:"
    ps aux | grep sky-eye-monitor | grep -v grep
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
    if [ -f "./sky-eye-monitor" ]; then
        echo "✅ 程序文件: 存在"
        ls -la sky-eye-monitor
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
echo "   启动服务: bash start-service.sh"
echo "   停止服务: bash stop-service.sh"
echo "   查看日志: tail -f logs/monitor.log"
echo "   编译程序: bash fix-go-env.sh"
