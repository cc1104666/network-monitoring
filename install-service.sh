#!/bin/bash

if [ "$EUID" -ne 0 ]; then
    echo "❌ 请使用sudo运行此脚本"
    exit 1
fi

SERVICE_NAME="sky-eye-monitor"
SERVICE_DIR="/opt/network-monitoring"
SERVICE_USER="skyeye"

echo "🔧 安装天眼监控系统服务..."

# 创建服务用户
if ! id "$SERVICE_USER" &>/dev/null; then
    echo "👤 创建服务用户: $SERVICE_USER"
    useradd -r -s /bin/false -d "$SERVICE_DIR" "$SERVICE_USER"
fi

# 设置目录权限
echo "📁 设置目录权限..."
chown -R "$SERVICE_USER:$SERVICE_USER" "$SERVICE_DIR"
chmod +x "$SERVICE_DIR/sky-eye-monitor"

# 创建systemd服务文件
echo "📝 创建systemd服务文件..."
cat > "/etc/systemd/system/$SERVICE_NAME.service" << EOF
[Unit]
Description=Sky Eye Network Monitoring System
After=network.target
Wants=network.target

[Service]
Type=simple
User=$SERVICE_USER
Group=$SERVICE_USER
WorkingDirectory=$SERVICE_DIR
ExecStart=$SERVICE_DIR/sky-eye-monitor
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=$SERVICE_NAME

# 安全设置
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$SERVICE_DIR

# 资源限制
LimitNOFILE=65536
LimitNPROC=4096

[Install]
WantedBy=multi-user.target
EOF

# 重新加载systemd
echo "🔄 重新加载systemd..."
systemctl daemon-reload

# 启用服务
echo "✅ 启用服务..."
systemctl enable "$SERVICE_NAME"

echo ""
echo "🎉 天眼监控系统服务安装完成！"
echo ""
echo "📋 服务管理命令:"
echo "  启动服务: sudo systemctl start $SERVICE_NAME"
echo "  停止服务: sudo systemctl stop $SERVICE_NAME"
echo "  重启服务: sudo systemctl restart $SERVICE_NAME"
echo "  查看状态: sudo systemctl status $SERVICE_NAME"
echo "  查看日志: sudo journalctl -u $SERVICE_NAME -f"
echo ""
echo "🌐 访问地址: http://localhost:8080"
echo ""

read -p "是否立即启动服务？(y/n): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "🚀 启动服务..."
    systemctl start "$SERVICE_NAME"
    systemctl status "$SERVICE_NAME"
fi
