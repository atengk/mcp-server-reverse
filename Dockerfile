# ==============================================================================
# mcp-server-reverse 容器化镜像构建配置 (支持 linux/amd64, linux/arm64)
#
# 内置 Python 3.12、uv、纯 Python 逆向内核 (lief + capstone + pefile)
# 以及外部增强工具链 (radare2 + binutils/objdump)，默认以 SSE 模式安全暴露服务。
# ==============================================================================

FROM python:3.14-slim

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy

# 安装外部逆向增强工具链 (radare2 提供伪代码反编译与 CFG，binutils 提供 objdump)
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        radare2 \
        binutils \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# 引入官方 uv 二进制
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

# 创建非 root 运行用户与只读样本沙箱目录
RUN useradd -m -u 1000 -s /bin/bash mcpuser \
    && mkdir -p /samples /app \
    && chown -R mcpuser:mcpuser /samples /app

WORKDIR /app

# 复制工程描述与源码并安装至系统环境
COPY pyproject.toml README.md LICENSE ./
COPY src/ ./src/

RUN uv pip install --system --no-cache .

USER mcpuser

# 默认开启 /samples 目录白名单沙箱并以 SSE 模式监听 8000 端口
ENV MCP_REVERSE_TRANSPORT=sse \
    MCP_REVERSE_HOST=0.0.0.0 \
    MCP_REVERSE_PORT=8000 \
    MCP_REVERSE_ALLOWED_DIRS=/samples

VOLUME ["/samples"]
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD ["mcp-server-reverse", "--check"]

ENTRYPOINT ["mcp-server-reverse"]
CMD ["--transport", "sse", "--host", "0.0.0.0", "--port", "8000"]
