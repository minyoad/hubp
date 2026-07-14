# 编译由 GitHub Actions 原生执行（利用 rust-cache 极速编译）
# Dockerfile 只负责打包预编译的二进制文件
FROM debian:stable-slim
ARG TARGETARCH
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates tzdata \
    && rm -rf /var/lib/apt/lists/*
RUN groupadd --system appgroup && useradd --system --no-create-home --gid appgroup appuser
ENV TZ=Asia/Shanghai
WORKDIR /app
COPY hubp-${TARGETARCH} /app/hubp
RUN chmod +x /app/hubp && chown -R appuser:appgroup /app
USER appuser
EXPOSE 45000
ENTRYPOINT ["/app/hubp"]
