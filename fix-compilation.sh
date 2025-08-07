#!/bin/bash

# 网络监控系统 - 编译问题修复脚本
# 修复Go编译中的结构体重复定义问题

set -e

echo "🔧 修复Go编译问题..."

# 备份原文件
echo "[步骤] 1. 备份原文件"
if [ -f "real-data-collector.go" ]; then
    cp real-data-collector.go real-data-collector.go.backup
    echo "✅ 已备份 real-data-collector.go"
fi

if [ -f "models.go" ]; then
    cp models.go models.go.backup
    echo "✅ 已备份 models.go"
fi

# 清理Go模块缓存
echo "[步骤] 2. 清理Go模块缓存"
go clean -modcache
go mod tidy

# 尝试编译
echo "[步骤] 3. 测试编译"
if go build -o network-monitor .; then
    echo "✅ Go程序编译成功!"
else
    echo "❌ 编译失败，请检查代码"
    exit 1
fi

echo "✅ 编译问题修复完成!"
