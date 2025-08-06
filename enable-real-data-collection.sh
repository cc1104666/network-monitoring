#!/bin/bash

echo "🔍 启用真实数据收集模式..."
echo "=================================="

# 设置Go环境变量
export PATH=$PATH:/usr/local/go/bin
export GOPROXY=https://goproxy.cn,direct
export GOSUMDB=sum.golang.google.cn
export GO111MODULE=on

# 检查Go是否可用
if ! command -v go &> /dev/null; then
    echo "❌ Go未找到，请先安装Go"
    echo "💡 运行: sudo bash install-and-fix-complete.sh"
    exit 1
fi

echo "✅ Go版本: $(go version)"

# 检查Go服务是否运行
if pgrep -f "network-monitoring" > /dev/null; then
    echo "⚠️  停止现有服务..."
    pkill -f "network-monitoring"
    sleep 2
fi

# 检查并创建必要的日志目录
echo "📁 创建日志目录..."
sudo mkdir -p /var/log/network-monitor
sudo chmod 755 /var/log/network-monitor

# 启用真实数据收集的环境变量
export ENABLE_REAL_DATA=true
export LOG_LEVEL=info

# 编译并启动服务
echo "🔨 编译服务..."
if go build -o network-monitoring *.go; then
    echo "✅ 编译成功"
else
    echo "❌ 编译失败"
    exit 1
fi

echo "🚀 启动真实数据收集模式..."
echo "📊 监控面板: http://localhost:8080"
echo "🔍 真实数据收集器已启用"
echo "📝 日志输出: /var/log/network-monitor/"

# 启动服务
ENABLE_REAL_DATA=true ./network-monitoring &

# 获取进程ID
PID=$!
echo "✅ 服务已启动 (PID: $PID)"

# 等待服务启动
sleep 3

# 检查服务状态
if ps -p $PID > /dev/null; then
    echo "✅ 服务运行正常"
    echo ""
    echo "📋 可用操作:"
    echo "  - 访问监控面板: http://localhost:8080"
    echo "  - 查看服务状态: ps aux | grep network-monitoring"
    echo "  - 停止服务: pkill -f network-monitoring"
    echo "  - 查看日志: tail -f /var/log/network-monitor/app.log"
    echo ""
    echo "🔄 系统现在正在收集真实的网络流量和系统数据"
else
    echo "❌ 服务启动失败"
    exit 1
fi
