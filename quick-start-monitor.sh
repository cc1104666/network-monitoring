#!/bin/bash

echo "⚡ 天眼监控系统 - 快速启动"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# 检查程序是否存在
if [ ! -f "./sky-eye-monitor-real" ]; then
    echo "📦 程序不存在，开始构建..."
    bash complete-fix-go-sum.sh
    
    if [ ! -f "./sky-eye-monitor-real" ]; then
        echo "❌ 构建失败，无法启动"
        exit 1
    fi
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

echo "🚀 启动监控系统..."

# 创建日志目录
mkdir -p logs

# 启动服务
nohup ./sky-eye-monitor-real > logs/monitor.log 2>&1 &

# 等待启动
sleep 3

# 检查状态
if pgrep -f "sky-eye-monitor-real" > /dev/null; then
    echo "✅ 服务启动成功！"
    
    # 获取服务器IP信息
    LOCAL_IP=$(hostname -I | awk '{print $1}')
    EXTERNAL_IP=$(curl -s --connect-timeout 5 ifconfig.me 2>/dev/null || echo "YOUR_SERVER_IP")
    
    echo ""
    echo "🎉 天眼监控系统运行中！"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "📊 访问地址:"
    echo "   本地访问: http://localhost:8080"
    echo "   内网访问: http://$LOCAL_IP:8080"
    echo "   外网访问: http://$EXTERNAL_IP:8080"
    echo ""
    echo "🔧 管理命令:"
    echo "   查看日志: tail -f logs/monitor.log"
    echo "   停止服务: pkill -f sky-eye-monitor-real"
    echo "   查看进程: ps aux | grep sky-eye-monitor-real"
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
