#!/bin/bash

# 确保以 root 用户权限运行
if [ "$EUID" -ne 0 ]; then
  echo "请使用 root 用户或在命令前添加 'sudo' 来运行该脚本。"
  exit
fi

# 更新软件包列表
echo "更新软件包列表..."
apt update

# 安装依赖软件
echo "安装依赖软件..."
apt install -y apt-transport-https ca-certificates curl software-properties-common git

# 添加 Docker GPG 密钥
echo "添加 Docker GPG 密钥..."
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg

# 添加 Docker 仓库
echo "添加 Docker 仓库..."
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] \
https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" > /etc/apt/sources.list.d/docker.list

# 安装 Docker 和 Docker Compose
echo "安装 Docker 和 Docker Compose..."
apt update
apt install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin

# 启动 Docker 服务并设置开机启动
echo "启动并设置 Docker 自启动..."
systemctl start docker
systemctl enable docker

# 验证 Docker 安装
echo "验证 Docker 安装..."
docker --version
docker compose version

# 创建工作目录
mkdir -p ~/Cloud
cd ~/Cloud

# 获取公网 IP 地址
echo "获取公网 IP 地址..."
PUBLIC_IP=$(curl -s https://ifconfig.me)
echo "获取到公网 IP: $PUBLIC_IP"

# 创建 docker-compose.yml 文件
echo "创建 docker-compose.yml 文件..."
cat <<EOF > docker-compose.yml
version: '3.4'

services:
  one-api:
    image: a37836323/new-zhuzhan-api:latest
    container_name: Cloud
    restart: always
    dns:
      - 1.1.1.1
      - 1.0.0.1
      - 8.8.8.8
    ports:
      - "3000:3000"
    volumes:
      - ./data:/data
    extra_hosts:
      - "host.docker.internal:host-gateway"
    environment:
      - SQL_DSN=Chatify:sk-chatify-MoLu154!@tcp(database.tenclock.shop:3306)/Cloud
      - SESSION_SECRET=Cloud
      - BATCH_UPDATE_ENABLED=true
      - BATCH_UPDATE_INTERVAL=15
      - GLOBAL_API_RATE_LIMIT=18000
      - SQL_MAX_OPEN_CONNS=10000
      - REDIS_CONN_STRING=redis://redis
      - TZ=Asia/Shanghai
      - SYNC_FREQUENCY=15
      - STREAMING_TIMEOUT=3000
      - NODE_TYPE=slave
      - GENERATE_DEFAULT_TOKEN=true
      - GLOBAL_IS_AGENT=0 # 是否是分站，1 表示分站，0 表示主站
    depends_on:
      - redis
    logging:
      driver: json-file
      options:
        max-size: "100m"
    healthcheck:
      test:
        - CMD-SHELL
        - |
          curl -f http://localhost:3000/api/status || exit 1
      interval: 30s
      timeout: 10s
      retries: 3

  redis:
    image: redis:latest
    container_name: redis-Cloud
    restart: always

  proxy:
    image: markusliu/go-proxy:latest
    container_name: proxy-Cloud
    ports:
      - "2888:2888"
    environment:
      - SERVER_PORT=2888
      - PUBLIC_IP=$PUBLIC_IP
      - IMAGE_STORAGE_PATH=/data/images
      - LOCAL_API_URL=http://$PUBLIC_IP:3000
    volumes:
      - ./data:/data
    restart: always
    extra_hosts:
      - "host.docker.internal:host-gateway"
    depends_on:
      - one-api

networks:
  default:
    driver: bridge
EOF

# 拉取所需的 Docker 镜像
echo "拉取所需的 Docker 镜像..."
docker pull a37836323/new-zhuzhan-api:latest
docker pull markusliu/go-proxy:latest
docker pull redis:latest

# 检查并删除已存在的容器
echo "检查并删除已存在的容器..."
if [ "$(docker ps -aq -f name=Cloud)" ]; then
    docker rm -f Cloud
fi
if [ "$(docker ps -aq -f name=redis-Cloud)" ]; then
    docker rm -f redis-Cloud
fi
if [ "$(docker ps -aq -f name=proxy-Cloud)" ]; then
    docker rm -f proxy-Cloud
fi

# 关闭 docker-compose 项目并移除孤立的容器
echo "关闭 docker-compose 项目并移除孤立的容器..."
docker compose down --remove-orphans

# 启动服务
echo "启动服务..."
docker compose up -d

# 等待几秒钟，确保容器启动
sleep 5

# 显示当前运行的容器状态
echo "当前运行的容器状态："
docker ps

echo "脚本执行完成。请根据需要检查服务是否正常运行。"
