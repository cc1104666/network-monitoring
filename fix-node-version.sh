#!/bin/bash

# 修复Node.js版本问题的脚本
# 此脚本将升级Node.js到兼容版本并重新安装依赖

set -e

echo "🔧 开始修复Node.js版本问题..."
echo "============================="

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_status() {
    echo -e "${GREEN}[信息]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[警告]${NC} $1"
}

print_error() {
    echo -e "${RED}[错误]${NC} $1"
}

print_step() {
    echo -e "${BLUE}[步骤]${NC} $1"
}

# 检查是否为root用户
if [[ $EUID -ne 0 ]]; then
   print_error "此脚本需要root权限运行，请使用 sudo"
   echo "使用方法: sudo ./fix-node-version.sh"
   exit 1
fi

print_step "1. 检查当前Node.js版本"
echo "[信息] 当前Node.js版本:"
node --version || echo "Node.js未安装或版本过低"

print_step "2. 卸载旧版本Node.js"
print_status "移除旧版本Node.js..."

# 停止可能运行的Node.js进程
pkill -f node || true

# 卸载通过apt安装的Node.js
apt-get remove -y nodejs npm || true
apt-get purge -y nodejs npm || true
apt-get autoremove -y || true

# 清理残留文件
rm -rf /usr/local/bin/node
rm -rf /usr/local/bin/npm
rm -rf /usr/local/lib/node_modules
rm -rf ~/.npm
rm -rf ~/.node-gyp

print_step "3. 安装Node.js 18.x"
print_status "下载并安装Node.js 18.x..."

# 添加NodeSource仓库
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -

# 安装Node.js 18.x
sudo apt-get install -y nodejs

# 验证安装
echo "[信息] 新的Node.js版本:"
node --version
npm --version

print_step "4. 清理旧的依赖"
print_status "清理现有的node_modules和package-lock.json..."

# 进入项目目录
cd /opt/network-monitoring

# 清理现有依赖
if [ -d "node_modules" ]; then
    rm -rf node_modules
    echo "✅ 已删除旧的node_modules"
fi

if [ -f "package-lock.json" ]; then
    rm -f package-lock.json
    echo "✅ 已删除旧的package-lock.json"
fi

print_step "5. 更新npm"
print_status "更新npm到最新版本..."

sudo npm install -g npm@latest

print_step "6. 重新安装依赖"
print_status "使用新版本Node.js安装依赖..."

# 设置npm配置
npm config set fund false
npm config set audit false

# 清理npm缓存
npm cache clean --force

# 安装依赖
npm install --no-optional --no-audit --no-fund

if [ $? -eq 0 ]; then
    print_status "✅ 依赖安装成功"
else
    print_error "❌ 依赖安装失败"
    exit 1
fi

print_step "7. 构建前端应用"
print_status "构建React应用..."

npm run build

if [ $? -eq 0 ]; then
    print_status "✅ 前端构建成功"
else
    print_error "❌ 前端构建失败"
    exit 1
fi

print_step "8. 验证修复结果"
print_status "验证Node.js和npm版本..."

echo ""
echo "🎉 修复完成！"
echo "=============="
echo ""
echo "📊 版本信息:"
echo "   Node.js: $(node --version)"
echo "   npm: $(npm --version)"
echo ""
echo "📁 项目状态:"
if [ -d "node_modules" ]; then
    echo "   ✅ node_modules 已创建"
else
    echo "   ❌ node_modules 未找到"
fi

if [ -d "out" ] || [ -d ".next" ]; then
    echo "   ✅ 前端构建完成"
else
    echo "   ❌ 前端构建未完成"
fi

echo ""
echo "🚀 现在可以继续部署:"
echo "   sudo ./deploy.sh"
echo "   或"
echo "   sudo ./simple-deploy.sh"
echo ""

print_status "Node.js版本修复完成！"
