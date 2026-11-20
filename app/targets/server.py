"""演示用目标 Web 服务。

同一进程监听：
* 8080/tcp HTTP（允许目标 172.31.10.10 与禁止目标 172.31.20.10 都运行本服务）；
* 8443/tcp HTTPS（使用受信演示 CA 签发的证书，含全部演示域名 SAN）。

按 Host 头提供不同路径行为：正常 200、跳转至允许/禁止目标、跳转链、
回显请求来源等。``/_requests`` 记录本进程收到的请求，供演示脚本验证
“被策略拒绝的目标从未收到探测请求”。
"""

from __future__ import annotations

import asyncio
import os
import time
from collections import deque

import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, PlainTextResponse, RedirectResponse
from fastapi.routing import APIRoute

CERT_DIR = os.getenv("CERT_DIR", "/app/certs")
TARGET_NAME = os.getenv("TARGET_NAME", "target")
RECENT_REQUESTS: deque[dict] = deque(maxlen=200)


class GetHeadRoute(APIRoute):
    """让所有 GET 路由同时接受 HEAD，便于 HEAD 探测返回真实状态码。"""

    def __init__(self, path: str, endpoint, **kwargs):  # noqa: ANN001
        methods = kwargs.get("methods")
        if methods:
            methods = set(methods)
            if "GET" in methods:
                methods.add("HEAD")
            kwargs["methods"] = methods
        super().__init__(path, endpoint, **kwargs)


app = FastAPI(title="demo-targets", docs_url=None, redoc_url=None, openapi_url=None)
app.router.route_class = GetHeadRoute


@app.middleware("http")
async def record_requests(request: Request, call_next):
    RECENT_REQUESTS.appendleft(
        {
            "ts": round(time.time(), 3),
            "method": request.method,
            "host": request.headers.get("host"),
            "path": request.url.path,
            "peer": request.client.host if request.client else None,
            "user_agent": request.headers.get("user-agent"),
        }
    )
    return await call_next(request)


@app.get("/")
async def root(request: Request):
    return JSONResponse(
        {
            "service": "demo-targets",
            "target": TARGET_NAME,
            "host": request.headers.get("host"),
            "peer": request.client.host if request.client else None,
            "tls": request.url.scheme == "https",
            "message": "目标可达",
        }
    )


@app.get("/healthz")
async def healthz():
    return PlainTextResponse("ok")


@app.get("/_requests")
async def list_requests():
    return JSONResponse(list(RECENT_REQUESTS))


@app.get("/redirect-allowed")
async def redirect_allowed():
    return RedirectResponse(url="http://redirect-final.demo.test/final", status_code=302)


@app.get("/redirect-https")
async def redirect_https():
    return RedirectResponse(
        url="https://https.allowed.demo.test/secure", status_code=302
    )


@app.get("/redirect-forbidden")
async def redirect_forbidden():
    # 跳到禁止网段的目标：探测方必须在第二跳解析校验时拦截
    return RedirectResponse(url="http://forbidden.demo.test/secret", status_code=302)


@app.get("/redirect-scheme")
async def redirect_scheme():
    # 跳到非 HTTP(S) 协议：探测方应拒绝
    return RedirectResponse(url="file:///etc/passwd", status_code=302)


@app.get("/final")
async def final():
    return JSONResponse({"message": "跳转链终点，可达"})


@app.get("/secure")
async def secure(request: Request):
    return JSONResponse(
        {
            "message": "HTTPS 目标可达，证书按原域名验证通过",
            "host": request.headers.get("host"),
            "scheme": request.url.scheme,
        }
    )


# 跳转链：loop1/loop/1 -> loop2/loop/2 -> loop3/loop/3 -> loop4/loop/4 -> loop1 …
@app.get("/loop/{n}")
async def loop_chain(n: int):
    next_n = 1 if n >= 4 else n + 1
    return RedirectResponse(
        url=f"http://loop{next_n}.demo.test/loop/{next_n}",
        status_code=307,
    )


@app.get("/secret")
async def secret():
    return JSONResponse({"message": "禁止网段目标不应被任何探测请求到达"})


def _server_kwargs() -> dict:
    return {
        "app": app,
        "log_level": "warning",
        "access_log": False,
        # 让目标端的 keep-alive 长于探测端的空闲上限（15 秒），
        # 演示期间连接不会先被目标端关掉。
        "timeout_keep_alive": 30,
    }


async def _one_server(port: int, ssl_cert: str | None = None,
                      ssl_key: str | None = None) -> uvicorn.Server:
    cfg_kwargs = dict(host="0.0.0.0", port=port, **_server_kwargs())
    if ssl_cert and ssl_key:
        cfg_kwargs.update(ssl_certfile=ssl_cert, ssl_keyfile=ssl_key)
    server = uvicorn.Server(uvicorn.Config(**cfg_kwargs))
    # 直接返回由 gather 驱动；这里只构造，不阻塞
    return server


async def serve() -> None:
    # 同时监听标准端口（80/443，供跳转 URL 直接使用）与演示端口（8080/8443）。
    # 容器以 root 启动可绑定特权端口；本地非特权演示可经环境变量改为高位端口。
    http_ports = [int(p) for p in os.getenv("TARGET_HTTP_PORTS", "80,8080").split(",")]
    https_ports = [int(p) for p in os.getenv("TARGET_HTTPS_PORTS", "443,8443").split(",")]
    cert = f"{CERT_DIR}/targets.fullchain.pem"
    key = f"{CERT_DIR}/targets.key.pem"
    servers: list[uvicorn.Server] = []
    for p in http_ports:
        servers.append(await _one_server(p))
    for p in https_ports:
        servers.append(await _one_server(p, cert, key))
    await asyncio.gather(*(s.serve() for s in servers))


if __name__ == "__main__":
    asyncio.run(serve())
