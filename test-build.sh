#!/bin/bash

echo "🧪 测试构建环境..."

# 设置Go环境
if [ -f "/usr/local/go/bin/go" ]; then
    export PATH=$PATH:/usr/local/go/bin
    GO_CMD="/usr/local/go/bin/go"
elif command -v go &> /dev/null; then
    GO_CMD="go"
else
    echo "❌ 未找到Go环境"
    exit 1
fi

echo "✅ Go版本: $($GO_CMD version)"

# 测试网络连接
echo "🌐 测试网络连接..."
if curl -s --connect-timeout 5 https://goproxy.cn > /dev/null; then
    echo "✅ 网络连接正常"
else
    echo "⚠️ 网络连接可能有问题"
fi

# 设置代理
export GOPROXY=https://goproxy.cn,direct
export GOSUMDB=sum.golang.google.cn
export GO111MODULE=on

echo "🔍 检查Go环境配置..."
echo "  GOPROXY: $GOPROXY"
echo "  GOSUMDB: $GOSUMDB"
echo "  GO111MODULE: $GO111MODULE"

# 测试基本命令
echo "🧪 测试Go命令..."
$GO_CMD env GOPROXY
$GO_CMD env GOSUMDB

echo "📁 当前目录文件:"
ls -la *.go

echo "✅ 环境检查完成，可以运行构建脚本"
