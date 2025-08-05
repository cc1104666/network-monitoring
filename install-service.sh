#!/bin/bash

echo "🔧 安装天眼监控系统为系统服务..."

SERVICE_NAME="sky-eye-monitor"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
WORK_DIR="/opt/network-monitoring"

# 检查是否为root用户
if [ "$EUID" -ne 0 ]; then
    echo "❌ 请使用root权限运行此脚本"
    echo "   sudo bash install-service.sh"
    exit 1
fi

# 检查可执行文件是否存在
if [ ! -f "$WORK_DIR/sky-eye-monitor" ]; then
    echo "❌ 可执行文件不存在: $WORK_DIR/sky-eye-monitor"
    echo "   请先运行编译脚本"
    exit 1
fi

# 创建systemd服务文件
echo "📝 创建systemd服务文件..."
cat > "$SERVICE_FILE" << EOF
[Unit]
Description=Sky Eye Network Monitoring System
Documentation=https://github.com/cc1104666/network-monitoring
After=network.target
Wants=network.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=$WORK_DIR
ExecStart=$WORK_DIR/sky-eye-monitor
ExecReload=/bin/kill -HUP \$MAINPID
KillMode=process
Restart=on-failure
RestartSec=5s

# 安全设置
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$WORK_DIR

# 资源限制
LimitNOFILE=65536
LimitNPROC=4096

# 日志设置
StandardOutput=journal
StandardError=journal
SyslogIdentifier=sky-eye-monitor

[Install]
WantedBy=multi-user.target
EOF

# 重新加载systemd配置
echo "🔄 重新加载systemd配置..."
systemctl daemon-reload

# 启用服务
echo "✅ 启用服务..."
systemctl enable "$SERVICE_NAME"

# 创建管理脚本的软链接
echo "🔗 创建管理命令..."
ln -sf "$WORK_DIR/service-manager.sh" "/usr/local/bin/sky-eye"
chmod +x "/usr/local/bin/sky-eye"

echo ""
echo "✅ 安装完成！"
echo ""
echo "📊 服务管理命令："
echo "  systemctl start $SERVICE_NAME     # 启动服务"
echo "  systemctl stop $SERVICE_NAME      # 停止服务"
echo "  systemctl restart $SERVICE_NAME   # 重启服务"
echo "  systemctl status $SERVICE_NAME    # 查看状态"
echo "  systemctl enable $SERVICE_NAME    # 开机自启"
echo "  systemctl disable $SERVICE_NAME   # 禁用自启"
echo ""
echo "📋 日志查看命令："
echo "  journalctl -u $SERVICE_NAME -f    # 实时查看日志"
echo "  journalctl -u $SERVICE_NAME -n 50 # 查看最近50行日志"
echo ""
echo "🎯 便捷管理命令："
echo "  sky-eye start    # 启动服务"
echo "  sky-eye stop     # 停止服务"
echo "  sky-eye status   # 查看状态"
echo "  sky-eye logs     # 查看日志"
echo ""
echo "🌐 访问地址："
echo "  http://localhost:8080"
echo "  http://$(hostname -I | awk '{print $1}'):8080"
echo ""

# 询问是否立即启动服务
read -p "是否立即启动服务？(y/n): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "🚀 启动服务..."
    systemctl start "$SERVICE_NAME"
    sleep 2
    systemctl status "$SERVICE_NAME" --no-pager
fi
