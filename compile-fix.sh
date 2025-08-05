#!/bin/bash

echo "🔧 修复编译问题并重新编译..."

# 清理之前的编译文件
rm -f sky-eye-monitor

# 重新编译
echo "🔨 重新编译..."
go build -ldflags="-s -w" -o sky-eye-monitor *.go

if [ $? -eq 0 ]; then
    echo "✅ 编译成功！"
    chmod +x sky-eye-monitor
    
    echo "📊 程序信息:"
    ls -lh sky-eye-monitor
    
    echo ""
    echo "🚀 可以启动服务了："
    echo "  前台运行: ./sky-eye-monitor"
    echo "  后台运行: nohup ./sky-eye-monitor > logs/monitor.log 2>&1 &"
    
else
    echo "❌ 编译仍然失败"
    echo "请检查错误信息："
    go build -v *.go
fi
