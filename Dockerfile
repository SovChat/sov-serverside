# ---------- 构建阶段 ----------
FROM golang:1.22-alpine AS builder

WORKDIR /app

# 先复制 go.mod 并下载依赖（利用 Docker 层缓存；go mod download 会顺带生成 go.sum）
COPY go.mod ./
RUN go mod download

# 复制源码并编译（CGO_ENABLED=0 生成静态二进制，便于在精简镜像中运行）
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /groupchat-server .

# ---------- 运行阶段 ----------
FROM alpine:3.20

# tzdata：保证容器内按本地时区正确切分按天的聊天日志
RUN apk add --no-cache ca-certificates tzdata

COPY --from=builder /groupchat-server /usr/local/bin/groupchat-server

# 数据目录（挂载卷持久化，服务器启动时会自动创建子目录结构）
RUN mkdir -p /data
VOLUME ["/data"]

EXPOSE 8443

ENTRYPOINT ["/usr/local/bin/groupchat-server"]
CMD ["-port=8443", "-dir=/data"]
