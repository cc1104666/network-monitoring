#!/bin/bash

SERVICE_NAME="sky-eye-monitor"
SERVICE_DIR="/opt/network-monitoring"
LOG_FILE="$SERVICE_DIR/monitor.log"
PID_FILE="$SERVICE_DIR/monitor.pid"

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 打印带颜色的消息
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

# 检查服务状态
check_status() {
    if [ -f "$PID_FILE" ]; then
        PID=$(cat "$PID_FILE")
        if ps -p $PID > /dev/null 2>&1; then
            return 0  # 运行中
        else
            rm -f "$PID_FILE"
            return 1  # 未运行
        fi
    else
        return 1  # 未运行
    fi
}

# 启动服务
start_service() {
    print_info "启动天眼监控系统..."
    
    if check_status; then
        print_warning "服务已经在运行中"
        return 0
    fi
    
    cd "$SERVICE_DIR"
    
    if [ ! -f "./sky-eye-monitor" ]; then
        print_error "可执行文件不存在，请先编译"
        return 1
    fi
    
    # 启动服务
    nohup ./sky-eye-monitor > "$LOG_FILE" 2>&1 &
    PID=$!
    echo $PID > "$PID_FILE"
    
    # 等待服务启动
    sleep 2
    
    if check_status; then
        print_status "服务启动成功 (PID: $PID)"
        print_info "访问地址: http://localhost:8080"
        print_info "查看日志: tail -f $LOG_FILE"
        return 0
    else
        print_error "服务启动失败"
        return 1
    fi
}

# 停止服务
stop_service() {
    print_info "停止天眼监控系统..."
    
    if ! check_status; then
        print_warning "服务未运行"
        return 0
    fi
    
    PID=$(cat "$PID_FILE")
    kill $PID
    
    # 等待进程结束
    for i in {1..10}; do
        if ! ps -p $PID > /dev/null 2>&1; then
            break
        fi
        sleep 1
    done
    
    # 强制杀死进程
    if ps -p $PID > /dev/null 2>&1; then
        print_warning "强制停止进程..."
        kill -9 $PID
    fi
    
    rm -f "$PID_FILE"
    print_status "服务已停止"
}

# 重启服务
restart_service() {
    print_info "重启天眼监控系统..."
    stop_service
    sleep 2
    start_service
}

# 查看服务状态
status_service() {
    print_info "检查服务状态..."
    
    if check_status; then
        PID=$(cat "$PID_FILE")
        print_status "服务正在运行 (PID: $PID)"
        
        # 显示进程信息
        echo ""
        echo "进程信息:"
        ps -p $PID -o pid,ppid,cmd,etime,pcpu,pmem
        
        # 显示端口信息
        echo ""
        echo "端口监听:"
        netstat -tlnp 2>/dev/null | grep ":8080" || ss -tlnp | grep ":8080"
        
        # 显示最近日志
        echo ""
        echo "最近日志 (最后10行):"
        tail -n 10 "$LOG_FILE" 2>/dev/null || echo "日志文件不存在"
        
    else
        print_error "服务未运行"
        return 1
    fi
}

# 查看日志
view_logs() {
    if [ -f "$LOG_FILE" ]; then
        print_info "实时查看日志 (按 Ctrl+C 退出):"
        tail -f "$LOG_FILE"
    else
        print_error "日志文件不存在: $LOG_FILE"
    fi
}

# 清理日志
clean_logs() {
    print_info "清理日志文件..."
    if [ -f "$LOG_FILE" ]; then
        > "$LOG_FILE"
        print_status "日志文件已清理"
    else
        print_warning "日志文件不存在"
    fi
}

# 显示帮助信息
show_help() {
    echo "天眼监控系统服务管理器"
    echo ""
    echo "用法: $0 {start|stop|restart|status|logs|clean|help}"
    echo ""
    echo "命令说明:"
    echo "  start   - 启动服务"
    echo "  stop    - 停止服务"
    echo "  restart - 重启服务"
    echo "  status  - 查看服务状态"
    echo "  logs    - 实时查看日志"
    echo "  clean   - 清理日志文件"
    echo "  help    - 显示帮助信息"
    echo ""
    echo "示例:"
    echo "  $0 start    # 启动服务"
    echo "  $0 status   # 查看状态"
    echo "  $0 logs     # 查看日志"
}

# 主程序
case "$1" in
    start)
        start_service
        ;;
    stop)
        stop_service
        ;;
    restart)
        restart_service
        ;;
    status)
        status_service
        ;;
    logs)
        view_logs
        ;;
    clean)
        clean_logs
        ;;
    help|--help|-h)
        show_help
        ;;
    *)
        echo "用法: $0 {start|stop|restart|status|logs|clean|help}"
        exit 1
        ;;
esac

exit $?
