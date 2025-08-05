#!/bin/bash

echo "🤖 安装天眼监控代理..."

# 配置参数
MASTER_URL="http://192.168.1.100:8080"  # 修改为你的主服务器地址
SERVER_NAME="$(hostname)"
SERVER_IP="$(hostname -I | awk '{print $1}')"

# 检查Go环境
if ! command -v go &> /dev/null; then
    echo "❌ 未找到Go语言环境，正在安装..."
    
    # 根据系统类型安装Go
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        # Ubuntu/Debian
        if command -v apt-get &> /dev/null; then
            sudo apt-get update
            sudo apt-get install -y golang-go
        # CentOS/RHEL
        elif command -v yum &> /dev/null; then
            sudo yum install -y golang
        fi
    fi
fi

# 创建代理目录
mkdir -p /opt/sky-eye-agent
cd /opt/sky-eye-agent

# 下载代理程序（这里假设你已经编译好了）
echo "📥 下载代理程序..."
# 你需要将编译好的程序上传到服务器或通过其他方式分发

# 创建配置文件
cat > agent.env << EOF
SERVER_NAME=$SERVER_NAME
SERVER_IP=$SERVER_IP
MASTER_URL=$MASTER_URL
EOF

# 创建启动脚本
cat > start-agent.sh << 'EOF'
#!/bin/bash
source ./agent.env
export SERVER_NAME SERVER_IP MASTER_URL
./sky-eye-monitor agent
EOF

chmod +x start-agent.sh

# 创建systemd服务
sudo tee /etc/systemd/system/sky-eye-agent.service > /dev/null << EOF
[Unit]
Description=Sky Eye Monitor Agent
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/sky-eye-agent
ExecStart=/opt/sky-eye-agent/start-agent.sh
Restart=always
RestartSec=10
StandardOutput=append:/var/log/sky-eye-agent.log
StandardError=append:/var/log/sky-eye-agent-error.log

[Install]
WantedBy=multi-user.target
EOF

# 启动服务
sudo systemctl daemon-reload
sudo systemctl enable sky-eye-agent
sudo systemctl start sky-eye-agent

echo "✅ 代理安装完成！"
echo "📊 主服务器: $MASTER_URL"
echo "🖥️  服务器名称: $SERVER_NAME"
echo "🌐 服务器IP: $SERVER_IP"
echo ""
echo "🔧 管理命令:"
echo "  查看状态: sudo systemctl status sky-eye-agent"
echo "  查看日志: sudo journalctl -u sky-eye-agent -f"
echo "  重启代理: sudo systemctl restart sky-eye-agent"
