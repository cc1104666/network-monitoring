#!/bin/bash

# 修复Node.js版本问题的脚本
# 此脚本将升级Node.js到兼容版本并重新安装依赖

set -e

echo "🔧 修复Node.js版本问题"
echo "======================"

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
if command -v node &> /dev/null; then
    CURRENT_NODE_VERSION=$(node --version)
    print_warning "当前Node.js版本: $CURRENT_NODE_VERSION (需要 >= 18.18.0)"
else
    print_warning "未找到Node.js"
fi

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
curl -fsSL https://deb.nodesource.com/setup_18.x | bash -

# 安装Node.js 18.x
apt-get install -y nodejs

# 验证安装
if command -v node &> /dev/null; then
    NEW_NODE_VERSION=$(node --version)
    NEW_NPM_VERSION=$(npm --version)
    print_status "✅ Node.js安装成功: $NEW_NODE_VERSION"
    print_status "✅ npm版本: $NEW_NPM_VERSION"
else
    print_error "❌ Node.js安装失败"
    exit 1
fi

print_step "4. 清理项目依赖"
print_status "清理现有的node_modules和package-lock.json..."

# 进入项目目录
cd /opt/network-monitoring

# 清理现有依赖
rm -rf node_modules
rm -f package-lock.json
rm -f npm-debug.log*

print_step "5. 更新package.json为兼容版本"
print_status "创建兼容的package.json..."

cat > package.json << 'EOF'
{
  "name": "network-monitoring-system",
  "version": "1.0.0",
  "private": true,
  "scripts": {
    "dev": "next dev",
    "build": "next build",
    "start": "next start",
    "lint": "next lint"
  },
  "dependencies": {
    "react": "^18.2.0",
    "react-dom": "^18.2.0",
    "next": "^14.0.0",
    "@types/node": "^18.0.0",
    "@types/react": "^18.2.0",
    "@types/react-dom": "^18.2.0",
    "typescript": "^5.0.0",
    "tailwindcss": "^3.3.0",
    "autoprefixer": "^10.4.0",
    "postcss": "^8.4.0",
    "lucide-react": "^0.294.0",
    "class-variance-authority": "^0.7.0",
    "clsx": "^2.0.0",
    "tailwind-merge": "^2.0.0"
  },
  "devDependencies": {
    "eslint": "^8.0.0",
    "eslint-config-next": "^14.0.0"
  },
  "engines": {
    "node": ">=18.18.0",
    "npm": ">=8.0.0"
  }
}
EOF

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
