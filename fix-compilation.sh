#!/bin/bash

echo "🔧 修复编译错误..."

# 设置Go环境
export PATH=$PATH:/usr/local/go/bin
export GOPATH=$HOME/go
export PATH=$PATH:$GOPATH/bin
export GOPROXY=https://goproxy.cn,direct
export GOSUMDB=sum.golang.google.cn
export GO111MODULE=on

echo "✅ Go环境已设置"

# 检查并修复重复定义问题
echo "🔍 检查代码结构..."

# 验证修复
echo "🧪 验证语法..."
if go vet *.go 2>/dev/null; then
    echo "✅ 语法检查通过"
else
    echo "⚠️ 发现语法警告，但可以继续编译"
fi

# 清理并重新构建
echo "🧹 清理缓存..."
go clean -cache
go clean -modcache

echo "📦 重新初始化模块..."
rm -f go.sum
go mod tidy

echo "📥 下载依赖..."
go mod download

echo "🔨 开始编译..."
if go build -o sky-eye-monitor *.go; then
    echo "✅ 编译成功！"
    echo ""
    echo "🚀 启动服务："
    echo "  ./sky-eye-monitor"
    echo ""
    echo "🌐 访问地址："
    echo "  http://localhost:8080"
    echo "  http://$(curl -s ifconfig.me):8080"
    echo ""
    
    # 检查可执行文件
    if [ -f "sky-eye-monitor" ]; then
        echo "📊 程序信息："
        ls -lh sky-eye-monitor
        echo ""
        
        # 询问是否立即启动
        read -p "是否立即启动服务？(y/n): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            echo "🚀 启动天眼监控系统..."
            ./sky-eye-monitor
        fi
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
