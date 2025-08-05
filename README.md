# 🚀 天眼网络监控系统部署指南

## 📋 系统要求

- **操作系统**: Linux (Ubuntu 18+, CentOS 7+)
- **Go语言**: 1.19+
- **内存**: 最少512MB
- **磁盘**: 最少1GB可用空间
- **网络**: 需要开放8080端口

## 🔧 快速部署

### 1. 部署主服务器

\`\`\`bash
# 克隆或下载项目文件
git clone <项目地址> 或 下载zip文件

# 进入项目目录
cd sky-eye-monitor

# 运行部署脚本
chmod +x deploy.sh
./deploy.sh
\`\`\`

### 2. 部署监控代理

在需要监控的服务器上执行：

\`\`\`bash
# 下载代理安装脚本
wget <安装脚本地址>/install-agent.sh

# 修改主服务器地址
vim install-agent.sh
# 将 MASTER_URL 改为你的主服务器地址

# 运行安装脚本
chmod +x install-agent.sh
./install-agent.sh
\`\`\`

## 🌐 访问系统

- **监控面板**: http://你的服务器IP:8080
- **本地访问**: http://localhost:8080

## 📊 功能特性

### ✅ 实时监控
- CPU、内存、磁盘使用率
- 网络流量统计
- 进程和负载监控
- 系统运行时间

### 🚨 威胁检测
- DDoS攻击检测
- 暴力破解检测
- 异常流量分析
- 实时告警通知

### 📱 多服务器支持
- 分布式监控代理
- 集中化管理面板
- 实时数据同步
- 自动故障检测

## 🔧 配置说明

### 主服务器配置 (config/config.yaml)

\`\`\`yaml
server:
  port: 8080
  host: "0.0.0.0"
  
monitoring:
  update_interval: 3s
  data_retention: 1000
  
threats:
  rate_limit_threshold: 1000
  brute_force_threshold: 50
  ddos_threshold: 10000
\`\`\`

### 代理配置 (agent.env)

\`\`\`bash
SERVER_NAME=Web服务器-1
SERVER_IP=192.168.1.10
MASTER_URL=http://192.168.1.100:8080
\`\`\`

## 🛠️ 管理命令

### 主服务器
\`\`\`bash
# 启动服务
sudo systemctl start sky-eye-monitor

# 停止服务
sudo systemctl stop sky-eye-monitor

# 重启服务
sudo systemctl restart sky-eye-monitor

# 查看状态
sudo systemctl status sky-eye-monitor

# 查看日志
sudo journalctl -u sky-eye-monitor -f
\`\`\`

### 监控代理
\`\`\`bash
# 启动代理
sudo systemctl start sky-eye-agent

# 停止代理
sudo systemctl stop sky-eye-agent

# 重启代理
sudo systemctl restart sky-eye-agent

# 查看状态
sudo systemctl status sky-eye-agent

# 查看日志
sudo journalctl -u sky-eye-agent -f
\`\`\`

## 🔍 故障排除

### 常见问题

1. **端口被占用**
   \`\`\`bash
   # 查看端口占用
   lsof -i :8080
   
   # 修改配置文件中的端口
   vim config/config.yaml
   \`\`\`

2. **代理连接失败**
   \`\`\`bash
   # 检查网络连通性
   telnet 主服务器IP 8080
   
   # 检查防火墙设置
   sudo ufw allow 8080
   \`\`\`

3. **权限问题**
   \`\`\`bash
   # 修改文件权限
   sudo chown -R $USER:$USER /opt/sky-eye-agent
   \`\`\`

## 📈 性能优化

- **数据保留**: 调整 `data_retention` 参数
- **更新频率**: 调整 `update_interval` 参数
- **内存使用**: 监控系统内存使用情况
- **网络带宽**: 考虑代理数据传输频率

## 🔒 安全建议

1. **防火墙配置**: 只开放必要端口
2. **访问控制**: 配置IP白名单
3. **HTTPS**: 生产环境建议使用HTTPS
4. **认证**: 添加用户认证机制

## 📞 技术支持

如有问题，请查看日志文件或联系技术支持。
