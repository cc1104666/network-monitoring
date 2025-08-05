#!/bin/bash

echo "🔧 修复编译错误..."

# 设置Go环境
export PATH=$PATH:/usr/local/go/bin
export GOPATH=$HOME/go
export PATH=$PATH:$GOPATH/bin
export GOPROXY=https://goproxy.cn,direct
export GOSUMDB=sum.golang.google.cn

echo "✅ Go环境已设置"

# 检查Go版本
if ! command -v go &> /dev/null; then
    echo "❌ Go未安装或未在PATH中"
    exit 1
fi

echo "🔍 检查代码结构..."

# 验证语法
echo "🧪 验证语法..."
go vet *.go 2>/dev/null || echo "⚠️ 发现语法警告，但可以继续编译"

# 清理缓存
echo "🧹 清理缓存..."
go clean -cache -modcache -i -r 2>/dev/null

# 重新初始化模块
echo "📦 重新初始化模块..."
go mod init network-monitor 2>/dev/null || true
go mod tidy

# 下载依赖
echo "📥 下载依赖..."
go mod download

# 编译
echo "🔨 开始编译..."
if go build -o sky-eye-monitor *.go; then
    echo "✅ 编译成功！"
    echo "🚀 可执行文件: ./sky-eye-monitor"
    echo ""
    echo "启动命令:"
    echo "  ./sky-eye-monitor        # 启动监控服务"
    echo "  ./sky-eye-monitor agent  # 启动代理模式"
    echo ""
    echo "访问地址: http://localhost:8080"
    
    # 询问是否立即启动
    read -p "是否立即启动服务? (y/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo "🚀 启动天眼监控系统..."
        ./sky-eye-monitor
    fi
else
    echo "❌ 编译失败"
    echo ""
    echo "🔍 详细错误信息："
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    go build -o sky-eye-monitor *.go
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    exit 1
fi
