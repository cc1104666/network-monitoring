#!/bin/bash

echo "🧹 清理构建环境..."

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

echo "🗑️ 清理文件..."
rm -f go.mod go.sum sky-eye-monitor

echo "🧹 清理Go缓存..."
$GO_CMD clean -cache
$GO_CMD clean -modcache

echo "📁 清理日志..."
rm -rf logs/*

echo "✅ 清理完成"
echo "现在可以运行: bash complete-build.sh"
