#!/bin/bash

echo "🔧 完整构建天眼监控系统..."

# 设置Go环境变量
if [ -f "/usr/local/go/bin/go" ]; then
    export PATH=$PATH:/usr/local/go/bin
    export GOPATH=$HOME/go
    export PATH=$PATH:$GOPATH/bin
    GO_CMD="/usr/local/go/bin/go"
elif command -v go &> /dev/null; then
    GO_CMD="go"
else
    echo "❌ 未找到Go环境"
    exit 1
fi

echo "✅ 使用Go: $($GO_CMD version)"

# 设置Go代理加速下载
export GOPROXY=https://goproxy.cn,direct
export GOSUMDB=sum.golang.google.cn
export GO111MODULE=on

echo "🧹 清理旧文件..."
rm -f go.sum sky-eye-monitor

echo "📦 重新初始化Go模块..."
$GO_CMD mod init network-monitor

echo "📥 下载依赖包..."

# 逐个添加依赖
echo "  添加 gorilla/mux..."
$GO_CMD get github.com/gorilla/mux@v1.8.1

echo "  添加 gorilla/websocket..."
$GO_CMD get github.com/gorilla/websocket@v1.5.1

echo "  添加 gopsutil..."
$GO_CMD get github.com/shirou/gopsutil/v3@v3.23.10

echo "🔄 整理依赖..."
$GO_CMD mod tidy

echo "⬇️ 下载所有依赖..."
$GO_CMD mod download

echo "✅ 验证依赖..."
$GO_CMD mod verify

echo "🔨 开始编译..."
$GO_CMD build -ldflags="-s -w" -o sky-eye-monitor *.go

if [ $? -eq 0 ]; then
    echo "✅ 编译成功！"
    chmod +x sky-eye-monitor
    
    echo "📊 程序信息:"
    ls -lh sky-eye-monitor
    
    echo ""
    echo "🎉 构建完成！"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "🚀 启动选项:"
    echo "  1. 前台运行: ./sky-eye-monitor"
    echo "  2. 后台运行: bash start-service.sh"
    echo "  3. 测试运行: timeout 10s ./sky-eye-monitor"
    echo ""
    
    # 询问是否立即启动
    read -p "是否现在启动服务？(y/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo "🚀 启动服务..."
        bash start-service.sh
    else
        echo "ℹ️ 稍后可运行 'bash start-service.sh' 启动服务"
    fi
    
else
    echo "❌ 编译失败"
    echo ""
    echo "🔍 详细错误信息:"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    $GO_CMD build -v *.go
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    echo ""
    echo "🛠️ 故障排除建议:"
    echo "1. 检查网络连接: curl -I https://goproxy.cn"
    echo "2. 清理缓存: $GO_CMD clean -modcache"
    echo "3. 重新下载: $GO_CMD mod download -x"
    echo "4. 检查代码语法: $GO_CMD vet *.go"
    
    exit 1
fi
