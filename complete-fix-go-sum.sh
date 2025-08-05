#!/bin/bash

echo "🔧 完整修复go.sum问题并重新构建..."

# 设置Go环境
export PATH=$PATH:/usr/local/go/bin
export GOPROXY=https://goproxy.cn,direct
export GOSUMDB=sum.golang.google.cn
export GO111MODULE=on

echo "✅ Go环境已设置"

# 停止现有服务
echo "🛑 停止现有服务..."
pkill -f "sky-eye-monitor" 2>/dev/null || true

# 完全清理Go模块
echo "🧹 完全清理Go模块..."
rm -rf go.mod go.sum
go clean -cache
go clean -modcache

# 重新初始化Go模块
echo "📦 重新初始化Go模块..."
go mod init network-monitor

# 按照错误提示下载依赖
echo "📥 下载依赖包..."
echo "  下载 gorilla/mux..."
go mod download github.com/gorilla/mux

echo "  下载 gorilla/websocket..."
go mod download github.com/gorilla/websocket

echo "  下载 gopsutil/v3..."
go mod download github.com/shirou/gopsutil/v3

# 添加依赖到go.mod
echo "📝 添加依赖到go.mod..."
go get github.com/gorilla/mux@v1.8.1
go get github.com/gorilla/websocket@v1.5.1
go get github.com/shirou/gopsutil/v3@v3.23.10

# 整理依赖
echo "🔄 整理依赖..."
go mod tidy

# 再次下载确保go.sum完整
echo "⬇️ 确保所有依赖下载完整..."
go mod download

# 验证依赖
echo "✅ 验证依赖..."
go mod verify

# 显示go.mod和go.sum状态
echo "📋 检查模块文件..."
if [ -f "go.mod" ]; then
    echo "✅ go.mod 存在"
    echo "内容:"
    cat go.mod
    echo ""
else
    echo "❌ go.mod 不存在"
fi

if [ -f "go.sum" ]; then
    echo "✅ go.sum 存在"
    echo "条目数量: $(wc -l < go.sum)"
    echo "前10行内容:"
    head -10 go.sum
    echo ""
else
    echo "❌ go.sum 不存在"
fi

# 编译
echo "🔨 开始编译..."
go build -ldflags="-s -w" -o sky-eye-monitor-real *.go

if [ $? -eq 0 ]; then
    echo "✅ 编译成功！"
    chmod +x sky-eye-monitor-real
    
    echo ""
    echo "📊 程序信息:"
    ls -lh sky-eye-monitor-real
    
    echo ""
    echo "🎉 真实数据监控系统编译完成！"
    echo ""
    echo "🚀 启动命令: ./start-real-monitor.sh"
    echo "📊 访问地址: http://localhost:8080"
    
    # 询问是否立即启动
    read -p "是否立即启动服务? (y/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        if [ -f "./start-real-monitor.sh" ]; then
            ./start-real-monitor.sh
        else
            echo "🚀 直接启动服务..."
            nohup ./sky-eye-monitor-real > monitor.log 2>&1 &
            echo "✅ 服务已在后台启动"
            echo "📊 访问地址: http://$(hostname -I | awk '{print $1}'):8080"
            echo "📝 查看日志: tail -f monitor.log"
        fi
    fi
    
else
    echo "❌ 编译失败"
    echo ""
    echo "🔍 详细错误信息："
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    go build -v -o sky-eye-monitor-real *.go
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    
    echo ""
    echo "🛠️ 故障排除建议:"
    echo "1. 检查网络连接: curl -I https://goproxy.cn"
    echo "2. 手动下载依赖: go mod download -x"
    echo "3. 检查Go版本: go version"
    echo "4. 清理并重试: go clean -cache && go mod download"
    
    exit 1
fi
