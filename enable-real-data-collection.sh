#!/bin/bash

echo "🔍 启用真实数据收集模式..."
echo "=================================="

# 设置Go环境变量
export PATH=$PATH:/usr/local/go/bin
export GOPROXY=https://goproxy.cn,direct

# 检查Go是否安装
if ! command -v go &> /dev/null; then
    echo "❌ Go未安装，请先安装Go"
    exit 1
fi

echo "✅ Go版本: $(go version)"

# 清理Go模块
echo "🧹 清理Go模块..."
rm -f go.mod go.sum
go clean -modcache

# 初始化Go模块
echo "📦 初始化Go模块..."
go mod init network-monitor

# 下载依赖
echo "📦 下载依赖..."
go mod tidy
go get github.com/gorilla/mux@latest
go get github.com/gorilla/websocket@latest
go get github.com/shirou/gopsutil/v3@latest

# 创建日志目录
echo "📁 创建日志目录..."
mkdir -p /var/log/network-monitor

# 设置环境变量启用真实数据收集
export ENABLE_REAL_DATA=true
echo "🔍 设置环境变量: ENABLE_REAL_DATA=true"

# 编译服务
echo "🔨 编译服务..."
if go build -o network-monitor .; then
    echo "✅ 编译成功"
    
    # 启动服务
    echo "🚀 启动网络监控服务..."
    echo "📊 访问地址: http://localhost:8080"
    echo "🔍 真实数据收集已启用"
    echo ""
    echo "按 Ctrl+C 停止服务"
    
    ENABLE_REAL_DATA=true ./network-monitor
else
    echo "❌ 编译失败"
    exit 1
fi
