# 构建阶段
FROM golang:tip-alpine3.21 AS builder

WORKDIR /app

# 安装构建依赖
RUN apk add --no-cache gcc musl-dev

# 复制源代码
COPY . .

# 构建应用
RUN go mod download
RUN CGO_ENABLED=0 GOOS=linux go build -o socks5-go ./cmd/main.go

# 运行阶段
FROM alpine:3.17

WORKDIR /app

# 从构建阶段复制二进制文件
COPY --from=builder /app/socks5-go .

# 暴露端口
EXPOSE 1080/tcp
EXPOSE 1080/udp

# 启动应用
ENTRYPOINT ["./socks5-go"] 
