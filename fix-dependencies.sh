#!/bin/bash

echo "🔧 修复Go依赖问题..."

# 清理现有的go.mod和go.sum
rm -f go.sum

# 重新初始化模块
echo "📦 重新初始化Go模块..."
go mod init network-monitor

# 添加依赖
echo "📥 添加必要依赖..."
go get github.com/gorilla/mux@v1.8.1
go get github.com/gorilla/websocket@v1.5.1
go get github.com/shirou/gopsutil/v3@v3.23.10

# 整理依赖
echo "🧹 整理依赖..."
go mod tidy

# 下载依赖
echo "⬇️ 下载依赖..."
go mod download

echo "✅ 依赖修复完成！"

# 尝试编译
echo "🔨 尝试编译..."
go build -o sky-eye-monitor *.go

if [ $? -eq 0 ]; then
    echo "✅ 编译成功！"
    echo "🚀 可以启动服务: ./sky-eye-monitor"
else
    echo "❌ 编译仍然失败，请检查代码"
fi
