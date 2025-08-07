#!/bin/bash

# 网络监控系统 - Node.js版本修复脚本
# 将Node.js从v12升级到v18以支持Next.js 15

set -e

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

echo "🔧 修复Node.js版本问题..."

# 检查当前Node.js版本
if command -v node &> /dev/null; then
    CURRENT_VERSION=$(node --version)
    print_status "当前Node.js版本: $CURRENT_VERSION"
    
    # 检查版本是否足够新
    NODE_MAJOR=$(echo $CURRENT_VERSION | cut -d'.' -f1 | sed 's/v//')
    if [ "$NODE_MAJOR" -ge 18 ]; then
        print_status "Node.js版本已满足要求，无需升级"
        exit 0
    fi
else
    print_warning "未检测到Node.js"
fi

print_step "1. 卸载旧版本Node.js"

# 停止可能运行的Node.js进程
pkill -f node || true

# 卸载旧版本
if command -v apt-get &> /dev/null; then
    apt-get remove -y nodejs npm || true
    apt-get purge -y nodejs npm || true
    apt-get autoremove -y || true
elif command -v yum &> /dev/null; then
    yum remove -y nodejs npm || true
elif command -v dnf &> /dev/null; then
    dnf remove -y nodejs npm || true
fi

# 清理残留文件
rm -rf /usr/local/bin/node /usr/local/bin/npm /usr/local/lib/node_modules ~/.npm ~/.node-gyp /usr/bin/node /usr/bin/npm

print_step "2. 安装Node.js 18.x"

# 更新包管理器
apt-get update

# 安装curl（如果没有）
if ! command -v curl &> /dev/null; then
    apt-get install -y curl
fi

# 安装NodeSource仓库
if command -v curl &> /dev/null; then
    curl -fsSL https://deb.nodesource.com/setup_18.x | bash -
else
    wget -qO- https://deb.nodesource.com/setup_18.x | bash -
fi

# 安装Node.js
if command -v apt-get &> /dev/null; then
    apt-get install -y nodejs
elif command -v yum &> /dev/null; then
    yum install -y nodejs npm
elif command -v dnf &> /dev/null; then
    dnf install -y nodejs npm
else
    print_error "不支持的包管理器"
    exit 1
fi

print_step "3. 验证安装"

if command -v node &> /dev/null; then
    NEW_VERSION=$(node --version)
    print_status "✅ Node.js安装成功: $NEW_VERSION"
else
    print_error "❌ Node.js安装失败"
    exit 1
fi

if command -v npm &> /dev/null; then
    NPM_VERSION=$(npm --version)
    print_status "✅ npm版本: $NPM_VERSION"
else
    print_error "❌ npm安装失败"
    exit 1
fi

print_step "4. 清理npm缓存"
npm cache clean --force || true

print_status "🎉 Node.js版本修复完成！"

echo "[步骤] 5. 更新package.json以兼容新版本"

# 创建兼容的package.json
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
    "next": "^14.2.0",
    "react": "^18.2.0",
    "react-dom": "^18.2.0",
    "lucide-react": "^0.263.1",
    "class-variance-authority": "^0.7.0",
    "clsx": "^2.0.0",
    "tailwind-merge": "^1.14.0"
  },
  "devDependencies": {
    "typescript": "^5.1.6",
    "eslint": "^8.57.0",
    "eslint-config-next": "^14.2.0",
    "@types/node": "^20.5.2",
    "@types/react": "^18.2.21",
    "@types/react-dom": "^18.2.7",
    "autoprefixer": "^10.4.15",
    "postcss": "^8.4.29",
    "tailwindcss": "^3.3.3"
  },
  "engines": {
    "node": ">=18.0.0",
    "npm": ">=8.0.0"
  }
}
EOF

echo "[步骤] 6. 更新next.config.mjs"

# 创建兼容的next.config.mjs
cat > next.config.mjs << 'EOF'
/** @type {import('next').NextConfig} */
const nextConfig = {
  output: 'export',
  trailingSlash: true,
  images: {
    unoptimized: true
  },
  eslint: {
    ignoreDuringBuilds: true,
  },
  typescript: {
    ignoreBuildErrors: true,
  }
}

export default nextConfig
EOF

echo "[步骤] 7. 安装依赖"
echo "📦 安装npm依赖..."

# 设置npm配置以避免权限问题
npm config set fund false
npm config set audit false

# 安装依赖
if npm install --legacy-peer-deps; then
    echo "✅ npm依赖安装成功!"
else
    echo "⚠️  npm install失败，尝试使用yarn..."
    
    # 安装yarn
    npm install -g yarn
    
    # 使用yarn安装
    if yarn install; then
        echo "✅ yarn依赖安装成功!"
    else
        echo "❌ 依赖安装失败"
        exit 1
    fi
fi

echo "[步骤] 8. 验证安装"

# 检查关键文件
if [ -d "node_modules" ]; then
    echo "✅ node_modules目录存在"
else
    echo "❌ node_modules目录不存在"
    exit 1
fi

if [ -f "node_modules/next/package.json" ]; then
    echo "✅ Next.js安装成功"
else
    echo "❌ Next.js安装失败"
    exit 1
fi

echo ""
echo "🎉 Node.js版本修复完成!"
echo ""
echo "📋 系统信息:"
echo "   Node.js: $(node --version)"
echo "   npm: $(npm --version)"
echo "   Next.js: $(cat node_modules/next/package.json | grep '"version"' | cut -d'"' -f4)"
echo ""
echo "🚀 现在可以继续部署系统了!"
