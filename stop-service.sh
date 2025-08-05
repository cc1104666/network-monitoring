#!/bin/bash

echo "🛑 停止天眼监控系统..."

# 查找进程
PIDS=$(pgrep -f sky-eye-monitor)

if [ -z "$PIDS" ]; then
    echo "ℹ️ 服务未运行"
    exit 0
fi

echo "发现运行中的进程: $PIDS"

# 优雅停止
echo "正在停止服务..."
pkill -TERM -f sky-eye-monitor

# 等待进程结束
sleep 3

# 检查是否还在运行
if pgrep -f sky-eye-monitor > /dev/null; then
    echo "⚠️ 进程未正常结束，强制终止..."
    pkill -KILL -f sky-eye-monitor
    sleep 1
fi

# 最终检查
if pgrep -f sky-eye-monitor > /dev/null; then
    echo "❌ 无法停止服务，请手动处理"
    echo "运行: kill -9 $(pgrep -f sky-eye-monitor)"
else
    echo "✅ 服务已停止"
fi
