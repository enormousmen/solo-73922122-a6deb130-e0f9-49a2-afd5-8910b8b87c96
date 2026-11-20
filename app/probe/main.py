"""FastAPI 出站探测 API。

* 全异步实现，慢探测不会阻塞事件循环与其他请求；
* 并发量由信号量保护，超出立即返回 429，不排队堆积；
* 单次探测有总超时，超时返回 408 并附带已完成的逐跳信息；
* ``POST /api/v1/probe`` 为多跳 GET/HEAD 探测；
* ``POST /api/v1/probe/head`` 为单跳 HEAD 探测，复用同源空闲连接。
"""

from __future__ import annotations

import asyncio
import time
from contextlib import asynccontextmanager
from dataclasses import asdict

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from .config import Settings, load_settings
from .connection_pool import IdleConnectionPool
from .dns_client import DnsResolver
from .head_probe import HeadProber
from .http_probe import Prober
from .policy import PolicyError


class ProbeRequest(BaseModel):
    url: str = Field(..., description="待探测的 http/https URL")
    method: str = Field("GET", description="HTTP 方法，仅支持 GET/HEAD")


class HeadProbeRequest(BaseModel):
    url: str = Field(..., description="待探测的 http/https URL（单跳 HEAD，不跟随跳转）")


class TlsReport(BaseModel):
    version: str
    cipher: str
    subject: str
    san: list[str]
    peer_cert_subject: str


class HopReportModel(BaseModel):
    hop: int = Field(..., description="跳序号，从 1 开始")
    url: str = Field(..., description="本跳请求的完整 URL")
    scheme: str
    hostname: str = Field(..., description="URL 中的主机名（证书校验与 Host 头均用它）")
    port: int
    resolved_addresses: list[str] = Field(
        ..., description="DNS 实际返回的全部 A 记录（IPv4）"
    )
    approved_addresses: list[str] = Field(
        ..., description="通过白名单校验的地址；整体被拒时为空列表"
    )
    connected_peer: str | None = Field(
        None, description="实际建立 TCP 连接的 ip:port，固定为已批准地址；未连接为 null"
    )
    connection_reused: bool = Field(
        False, description="是否复用了空闲连接（仅单跳 HEAD 探测会为 true）"
    )
    connection_kept_alive: bool = Field(
        False, description="本次连接是否已归还空闲池（仅单跳 HEAD 探测）"
    )
    tls: dict | None = Field(None, description="HTTPS 时的 TLS 版本、套件与证书信息")
    request_sent: bool = Field(
        ..., description="是否真正发出 HTTP 请求；被策略拒绝时恒为 false"
    )
    status_code: int | None = Field(None, description="HTTP 响应状态码")
    reason: str | None
    location: str | None = Field(None, description="3xx 响应的 Location 头")
    redirect_count: int
    outcome: str = Field(
        ..., description="ok | redirected | blocked | error"
    )
    reject_reason: str | None = Field(None, description="策略拒绝原因（面向白名单调整）")
    error: str | None = Field(None, description="连接/TLS/读取等错误原因")


class ProbeResponse(BaseModel):
    requested_url: str
    method: str
    outcome: str = Field(..., description="ok | blocked | error | timeout")
    summary: str = Field(..., description="人类可读的结论摘要")
    hops: list[HopReportModel] = Field(..., description="逐跳探测报告")
    allowed_cidrs: list[str] = Field(..., description="本次启动生效的 IPv4 白名单")
    dns_server: str
    max_redirects: int
    elapsed_ms: int = Field(..., description="整次探测耗时（毫秒）")


class PolicyResponse(BaseModel):
    allowed_cidrs: list[str]
    dns_server: str
    dns_port: int
    ip_versions: list[str]
    max_redirects: int
    tls_verify: bool
    ca_bundle: str | None
    timeouts: dict
    connection_pool: dict


class HeadProbeResponse(BaseModel):
    requested_url: str
    method: str = Field("HEAD", description="固定为 HEAD（单跳，不跟随跳转）")
    outcome: str = Field(..., description="ok | redirected | blocked | error | timeout")
    summary: str = Field(..., description="人类可读的结论摘要")
    hop: HopReportModel = Field(..., description="本次单跳探测报告")
    allowed_cidrs: list[str]
    dns_server: str
    elapsed_ms: int
    pool: dict = Field(..., description="探测结束后的空闲连接池状态")


settings: Settings = load_settings()
resolver = DnsResolver(
    settings.dns_server,
    port=settings.dns_port,
    timeout=settings.dns_timeout,
    retries=settings.dns_retries,
)
prober = Prober(
    policy=settings.policy,
    resolver=resolver,
    ca_bundle=settings.ca_bundle,
    connect_timeout=settings.connect_timeout,
    read_timeout=settings.read_timeout,
    tls_timeout=settings.tls_timeout,
    max_redirects=settings.max_redirects,
)
pool = IdleConnectionPool(
    max_idle=settings.max_idle_connections,
    idle_timeout=settings.idle_timeout,
)
head_prober = HeadProber(
    policy=settings.policy,
    resolver=resolver,
    pool=pool,
    ca_bundle=settings.ca_bundle,
    connect_timeout=settings.connect_timeout,
    read_timeout=settings.read_timeout,
    tls_timeout=settings.tls_timeout,
)
_semaphore = asyncio.Semaphore(settings.max_concurrency)


@asynccontextmanager
async def lifespan(app: FastAPI):
    try:
        yield
    finally:
        await pool.aclose()


app = FastAPI(
    title="出站探测 API（Egress Probe）",
    version="1.1.0",
    description=(
        "提交 HTTP/HTTPS URL，返回逐跳状态、DNS 解析地址、实际连接地址与拒绝原因。"
        "仅支持 IPv4；每跳全部解析地址均在启动时配置的 CIDR 白名单内才会连接；"
        "最多跟随 3 次跳转；被拒目标不会收到任何探测请求；HTTPS 始终按原域名验证证书。"
        "另有单跳 HEAD 接口，可复用同源且对端仍获准的空闲连接。"
    ),
    lifespan=lifespan,
)


@app.get("/healthz", tags=["meta"])
async def healthz() -> dict:
    return {"status": "ok", "service": "egress-probe"}


@app.get("/api/v1/policy", response_model=PolicyResponse, tags=["meta"])
async def get_policy() -> PolicyResponse:
    return PolicyResponse(
        allowed_cidrs=settings.allowed_cidrs,
        dns_server=settings.dns_server,
        dns_port=settings.dns_port,
        ip_versions=["IPv4"],
        max_redirects=settings.max_redirects,
        tls_verify=True,
        ca_bundle=settings.ca_bundle,
        timeouts={
            "dns": settings.dns_timeout,
            "connect": settings.connect_timeout,
            "tls": settings.tls_timeout,
            "read": settings.read_timeout,
            "overall": settings.overall_timeout,
        },
        connection_pool={
            "max_idle_connections": settings.max_idle_connections,
            "idle_timeout_seconds": settings.idle_timeout,
            **pool.stats(),
        },
    )


@app.post("/api/v1/probe", response_model=ProbeResponse, tags=["probe"])
async def create_probe(req: ProbeRequest) -> ProbeResponse:
    method = req.method.upper()
    if method not in ("GET", "HEAD"):
        raise HTTPException(status_code=422, detail="仅支持 GET/HEAD 方法")

    started = time.monotonic()
    # 单事件循环内，locked() 检查与后续 acquire 之间没有 await，判定是原子的
    if _semaphore.locked():
        raise HTTPException(
            status_code=429,
            detail=(
                f"探测并发已达上限 {settings.max_concurrency}，"
                "为避免慢探测互相阻塞，请求被拒绝，请稍后重试"
            ),
        )

    async with _semaphore:
        try:
            hops = await asyncio.wait_for(
                prober.probe(req.url, method=method),
                timeout=settings.overall_timeout,
            )
        except PolicyError as exc:
            # 入口级静态错误（如非法 URL）：未产生任何流量
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        except asyncio.TimeoutError:
            elapsed = int((time.monotonic() - started) * 1000)
            raise HTTPException(
                status_code=408,
                detail={
                    "message": f"探测总超时（{settings.overall_timeout}s）",
                    "elapsed_ms": elapsed,
                },
            ) from None

    elapsed_ms = int((time.monotonic() - started) * 1000)
    last = hops[-1]
    if last.outcome == "blocked":
        outcome = "blocked"
        summary = f"第 {last.hop} 跳被策略拒绝: {last.reject_reason}"
    elif last.outcome == "error":
        outcome = "error"
        summary = f"第 {last.hop} 跳出错: {last.error}"
    else:
        outcome = "ok"
        summary = f"探测完成，共 {len(hops)} 跳，最终状态码 {last.status_code}"

    return ProbeResponse(
        requested_url=req.url,
        method=method,
        outcome=outcome,
        summary=summary,
        hops=[HopReportModel(**asdict(h)) for h in hops],
        allowed_cidrs=settings.allowed_cidrs,
        dns_server=f"{settings.dns_server}:{settings.dns_port}",
        max_redirects=settings.max_redirects,
        elapsed_ms=elapsed_ms,
    )


@app.post(
    "/api/v1/probe/head",
    response_model=HeadProbeResponse,
    tags=["probe"],
    summary="单跳 HEAD 探测（可复用空闲连接）",
    description=(
        "发送一次 HEAD 请求，不跟随跳转；返回状态码、实际对端地址、是否复用连接，"
        "3xx 时返回 Location。每次探测都重新解析域名并对全部地址做 IPv4 CIDR 白名单"
        "校验；仅当空闲连接与目标同源且实际对端仍在本次获准地址中时才复用；"
        "收齐最终响应头且允许保活才归还连接池；请求可能已发出时失败不补发。"
    ),
)
async def create_head_probe(req: HeadProbeRequest) -> HeadProbeResponse:
    """单跳 HEAD 探测：不跟随跳转，返回状态码、实际对端与连接复用情况。

    每次探测重新解析域名并做全量白名单校验；空闲连接仅在同源且实际
    对端仍属本次获准地址时才复用。
    """
    started = time.monotonic()
    if _semaphore.locked():
        raise HTTPException(
            status_code=429,
            detail=(
                f"探测并发已达上限 {settings.max_concurrency}，"
                "为避免慢探测互相阻塞，请求被拒绝，请稍后重试"
            ),
        )

    async with _semaphore:
        try:
            report = await asyncio.wait_for(
                head_prober.probe(req.url),
                timeout=settings.overall_timeout,
            )
        except PolicyError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        except asyncio.TimeoutError:
            elapsed = int((time.monotonic() - started) * 1000)
            raise HTTPException(
                status_code=408,
                detail={
                    "message": f"探测总超时（{settings.overall_timeout}s）",
                    "elapsed_ms": elapsed,
                },
            ) from None

    elapsed_ms = int((time.monotonic() - started) * 1000)
    if report.outcome == "blocked":
        outcome = "blocked"
        summary = f"探测被策略拒绝: {report.reject_reason}"
    elif report.outcome == "error":
        outcome = "error"
        summary = f"探测出错: {report.error}"
    elif report.outcome == "redirected":
        outcome = "redirected"
        summary = (
            f"HEAD 探测完成，状态码 {report.status_code}，"
            f"未跟随跳转，Location: {report.location}"
        )
    else:
        outcome = "ok"
        summary = (
            f"HEAD 探测完成，状态码 {report.status_code}，"
            f"{'复用空闲连接' if report.connection_reused else '新建连接'}"
            f"（实际对端 {report.connected_peer}）"
        )

    hop_fields = asdict(report)
    hop_fields.update(hop=1, redirect_count=0)
    return HeadProbeResponse(
        requested_url=req.url,
        outcome=outcome,
        summary=summary,
        hop=HopReportModel(**hop_fields),
        allowed_cidrs=settings.allowed_cidrs,
        dns_server=f"{settings.dns_server}:{settings.dns_port}",
        elapsed_ms=elapsed_ms,
        pool=pool.stats(),
    )
