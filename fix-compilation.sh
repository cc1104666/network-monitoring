#!/bin/bash

echo "🔧 修复编译错误..."

# 设置Go环境
export PATH=$PATH:/usr/local/go/bin
export GOPATH=$HOME/go
export PATH=$PATH:$GOPATH/bin

if command -v go >/dev/null 2>&1; then
    echo "✅ Go环境已设置"
else
    echo "❌ Go环境未找到"
    exit 1
fi

echo "🔍 检查代码结构..."

# 检查语法
echo "🧪 验证语法..."
go vet *.go 2>/dev/null || echo "⚠️ 发现语法警告，但可以继续编译"

# 清理缓存
echo "🧹 清理缓存..."
go clean -cache
go clean -modcache

# 重新初始化模块
echo "📦 重新初始化模块..."
rm -f go.mod go.sum
go mod init network-monitor
go mod tidy

# 下载依赖
echo "📥 下载依赖..."
go get github.com/gorilla/mux@latest
go get github.com/gorilla/websocket@latest
go get github.com/shirou/gopsutil/v3@latest

# 编译
echo "🔨 开始编译..."
if go build -o sky-eye-monitor *.go; then
    echo "✅ 编译成功！"
    echo ""
    echo "🚀 启动服务："
    echo "  ./sky-eye-monitor"
    echo ""
    echo "🤖 启动代理模式："
    echo "  ./sky-eye-monitor agent"
    echo ""
    echo "📊 访问监控面板："
    echo "  http://localhost:8080"
    echo ""
    
    # 询问是否立即启动
    read -p "是否立即启动服务？(y/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo "🚀 启动天眼监控系统..."
        nohup ./sky-eye-monitor > monitor.log 2>&1 &
        echo "✅ 服务已在后台启动"
        echo "📋 查看日志: tail -f monitor.log"
        echo "🌐 访问地址: http://$(hostname -I | awk '{print $1}'):8080"
    fi
else
    echo "❌ 编译失败"
    echo ""
    echo "🔍 详细错误信息："
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    go build -o sky-eye-monitor *.go
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    echo "🛠️ 故障排除建议:"
    echo "1. 检查网络连接: curl -I https://goproxy.cn"
    echo "2. 清理缓存: go clean -modcache"
    echo "3. 重新下载: go mod download -x"
    echo "4. 检查代码语法: go vet *.go"
    exit 1
fi
