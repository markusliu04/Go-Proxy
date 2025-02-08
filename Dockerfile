FROM golang:1.21-alpine

WORKDIR /app

# 安装基础工具
RUN apk add --no-cache ca-certificates

# 复制 go.mod 和 go.sum（如果存在）
COPY go.* ./

# 下载依赖
RUN go mod download

# 复制源代码
COPY . .

# 编译
RUN CGO_ENABLED=0 GOOS=linux go build -o proxy

EXPOSE 2888

CMD ["./proxy"] 