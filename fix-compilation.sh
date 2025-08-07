#!/bin/bash

# 网络监控系统 - 编译问题修复脚本
# 修复Go编译中的结构体重复定义问题

set -e

echo "🔧 修复Go编译问题..."

# 备份原文件
echo "[步骤] 1. 备份原文件"
if [ -f "real-data-collector.go" ]; then
    cp real-data-collector.go real-data-collector.go.backup.$(date +%s)
    echo "✅ 已备份 real-data-collector.go"
fi

if [ -f "models.go" ]; then
    cp models.go models.go.backup.$(date +%s)
    echo "✅ 已备份 models.go"
fi

# 清理Go模块缓存
echo "[步骤] 2. 清理Go模块缓存"
go clean -modcache
go clean -cache

# 重新初始化模块
echo "[步骤] 3. 重新初始化Go模块"
rm -f go.mod go.sum
go mod init network-monitor
go mod tidy

# 下载依赖
echo "[步骤] 4. 下载Go依赖"
go get github.com/gorilla/mux@latest
go get github.com/gorilla/websocket@latest
go get github.com/shirou/gopsutil/v3@latest
go get github.com/rs/cors@latest

# 尝试编译
echo "[步骤] 5. 测试编译"
if go build -o network-monitor .; then
    echo "✅ Go程序编译成功!"
    echo ""
    echo "🎯 编译产物:"
    ls -la network-monitor
    echo ""
    echo "📊 文件大小: $(du -h network-monitor | cut -f1)"
else
    echo "❌ 编译失败，显示详细错误信息:"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    go build -v -o network-monitor . 2>&1 || true
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    exit 1
fi

echo "✅ 编译问题修复完成!"
