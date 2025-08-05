#!/bin/bash

echo "🔧 修复Go环境变量问题..."

# 检查Go是否已安装
if [ -f "/usr/local/go/bin/go" ]; then
    echo "✅ 发现Go安装在 /usr/local/go/"
    
    # 设置当前会话的环境变量
    export PATH=$PATH:/usr/local/go/bin
    export GOPATH=$HOME/go
    export PATH=$PATH:$GOPATH/bin
    
    # 验证Go命令
    if /usr/local/go/bin/go version; then
        echo "✅ Go环境设置成功"
        
        # 创建Go工作目录
        mkdir -p $GOPATH/bin
        
        echo "🔨 开始编译..."
        
        # 清理之前的编译文件
        rm -f sky-eye-monitor
        
        # 设置Go代理
        export GOPROXY=https://goproxy.cn,direct
        export GOSUMDB=sum.golang.google.cn
        
        # 编译程序
        /usr/local/go/bin/go build -ldflags="-s -w" -o sky-eye-monitor *.go
        
        if [ $? -eq 0 ]; then
            echo "✅ 编译成功！"
            chmod +x sky-eye-monitor
            
            echo "📊 程序信息:"
            ls -lh sky-eye-monitor
            
            echo ""
            echo "🚀 启动服务："
            echo "  测试启动: ./sky-eye-monitor"
            echo "  后台启动: nohup ./sky-eye-monitor > logs/monitor.log 2>&1 &"
            echo "  查看日志: tail -f logs/monitor.log"
            echo "  停止服务: pkill -f sky-eye-monitor"
            
            # 询问是否立即启动
            read -p "是否现在启动服务？(y/n): " -n 1 -r
            echo
            if [[ $REPLY =~ ^[Yy]$ ]]; then
                echo "🚀 启动服务..."
                mkdir -p logs
                nohup ./sky-eye-monitor > logs/monitor.log 2>&1 &
                
                sleep 3
                
                if pgrep -f sky-eye-monitor > /dev/null; then
                    echo "✅ 服务启动成功！"
                    
                    # 获取服务器IP
                    LOCAL_IP=$(hostname -I | awk '{print $1}')
                    EXTERNAL_IP=$(curl -s --connect-timeout 5 ifconfig.me 2>/dev/null || echo "YOUR_SERVER_IP")
                    
                    echo ""
                    echo "🎉 天眼监控系统运行中！"
                    echo "📊 本地访问: http://localhost:8080"
                    echo "📊 内网访问: http://$LOCAL_IP:8080"
                    echo "📊 外网访问: http://$EXTERNAL_IP:8080"
                    echo ""
                    echo "📝 查看日志: tail -f logs/monitor.log"
                    echo "🛑 停止服务: pkill -f sky-eye-monitor"
                else
                    echo "❌ 服务启动失败，查看日志:"
                    cat logs/monitor.log
                fi
            fi
            
        else
            echo "❌ 编译失败，详细错误信息："
            /usr/local/go/bin/go build -v *.go
        fi
        
    else
        echo "❌ Go命令执行失败"
    fi
    
elif command -v go &> /dev/null; then
    echo "✅ 发现系统Go环境"
    go version
    
    echo "🔨 开始编译..."
    
    # 清理之前的编译文件
    rm -f sky-eye-monitor
    
    # 设置Go代理
    export GOPROXY=https://goproxy.cn,direct
    export GOSUMDB=sum.golang.google.cn
    
    # 编译程序
    go build -ldflags="-s -w" -o sky-eye-monitor *.go
    
    if [ $? -eq 0 ]; then
        echo "✅ 编译成功！"
        chmod +x sky-eye-monitor
        
        echo "📊 程序信息:"
        ls -lh sky-eye-monitor
        
        echo ""
        echo "🚀 可以启动服务了："
        echo "  ./sky-eye-monitor"
    else
        echo "❌ 编译失败"
    fi
    
else
    echo "❌ 未找到Go环境，需要重新安装"
    echo "请运行: bash deploy.sh"
fi
