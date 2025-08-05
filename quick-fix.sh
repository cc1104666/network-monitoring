#!/bin/bash

echo "🔧 快速修复编译问题..."

# 进入项目目录
cd /opt/network-monitoring-system

# 清理旧文件
echo "🧹 清理旧文件..."
rm -f go.mod go.sum sky-eye-monitor

# 重新初始化Go模块
echo "📦 重新初始化Go模块..."
go mod init network-monitor

# 添加依赖
echo "📥 添加依赖..."
go get github.com/gorilla/mux@v1.8.1
go get github.com/gorilla/websocket@v1.5.1
go get github.com/shirou/gopsutil/v3@v3.23.10

# 整理依赖
go mod tidy

# 编译
echo "🔨 编译程序..."
go build -o sky-eye-monitor *.go

if [ $? -eq 0 ]; then
    echo "✅ 编译成功！"
    chmod +x sky-eye-monitor
    
    # 启动测试
    echo "🚀 启动服务..."
    nohup ./sky-eye-monitor > logs/monitor.log 2>&1 &
    
    sleep 3
    
    if pgrep -f sky-eye-monitor > /dev/null; then
        echo "✅ 服务启动成功！"
        echo "📊 访问地址: http://$(curl -s ifconfig.me):8080"
        echo "📝 查看日志: tail -f logs/monitor.log"
        echo "🛑 停止服务: pkill -f sky-eye-monitor"
    else
        echo "❌ 服务启动失败，查看日志: cat logs/monitor.log"
    fi
else
    echo "❌ 编译失败"
    exit 1
fi
