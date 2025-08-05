#!/bin/bash

SERVICE_NAME="sky-eye-monitor"
SERVICE_DIR="/opt/network-monitoring"
SERVICE_BIN="$SERVICE_DIR/sky-eye-monitor"
PID_FILE="/var/run/$SERVICE_NAME.pid"
LOG_FILE="/var/log/$SERVICE_NAME.log"

case "$1" in
    start)
        echo "🚀 启动天眼监控服务..."
        if [ -f "$PID_FILE" ]; then
            PID=$(cat "$PID_FILE")
            if ps -p $PID > /dev/null 2>&1; then
                echo "⚠️ 服务已在运行 (PID: $PID)"
                exit 1
            else
                rm -f "$PID_FILE"
            fi
        fi
        
        cd "$SERVICE_DIR"
        nohup "$SERVICE_BIN" > "$LOG_FILE" 2>&1 &
        echo $! > "$PID_FILE"
        echo "✅ 服务启动成功 (PID: $(cat $PID_FILE))"
        echo "📊 访问地址: http://localhost:8080"
        ;;
        
    stop)
        echo "🛑 停止天眼监控服务..."
        if [ -f "$PID_FILE" ]; then
            PID=$(cat "$PID_FILE")
            if ps -p $PID > /dev/null 2>&1; then
                kill $PID
                rm -f "$PID_FILE"
                echo "✅ 服务已停止"
            else
                echo "⚠️ 服务未运行"
                rm -f "$PID_FILE"
            fi
        else
            echo "⚠️ PID文件不存在，服务可能未运行"
        fi
        ;;
        
    restart)
        $0 stop
        sleep 2
        $0 start
        ;;
        
    status)
        if [ -f "$PID_FILE" ]; then
            PID=$(cat "$PID_FILE")
            if ps -p $PID > /dev/null 2>&1; then
                echo "✅ 服务正在运行 (PID: $PID)"
                echo "📊 访问地址: http://localhost:8080"
                echo "📝 日志文件: $LOG_FILE"
            else
                echo "❌ 服务未运行 (PID文件存在但进程不存在)"
                rm -f "$PID_FILE"
            fi
        else
            echo "❌ 服务未运行"
        fi
        ;;
        
    logs)
        if [ -f "$LOG_FILE" ]; then
            echo "📝 查看服务日志 (按Ctrl+C退出):"
            tail -f "$LOG_FILE"
        else
            echo "⚠️ 日志文件不存在: $LOG_FILE"
        fi
        ;;
        
    *)
        echo "使用方法: $0 {start|stop|restart|status|logs}"
        echo ""
        echo "命令说明:"
        echo "  start   - 启动服务"
        echo "  stop    - 停止服务"
        echo "  restart - 重启服务"
        echo "  status  - 查看服务状态"
        echo "  logs    - 查看服务日志"
        exit 1
        ;;
esac
