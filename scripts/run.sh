#!/bin/bash

echo "启动天眼网络监控系统..."

# 检查Go是否安装
if ! command -v go &> /dev/null; then
    echo "错误: 未找到Go语言环境，请先安装Go"
    exit 1
fi

# 创建必要的目录
mkdir -p static

# 下载依赖
echo "下载依赖包..."
go mod tidy

# 编译并运行
echo "编译并启动服务器..."
go run *.go
