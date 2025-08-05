#!/bin/bash

echo "⚡ 天眼监控系统 - 快速启动"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# 检查程序是否存在
if [ ! -f "./sky-eye-monitor" ]; then
    echo "📦 程序不存在，开始构建..."
    bash complete-build.sh
    
    if [ ! -f "./sky-eye-monitor" ]; then
        echo "❌ 构建失败，无法启动"
        exit 1
    fi
fi

echo "🚀 启动监控系统..."
bash start-service.sh

# 等待启动
sleep 2

# 检查状态
bash status-service.sh
