"""单跳 HTTP/HTTPS HEAD 探测（带同源空闲连接复用）。

与多跳 GET 探测的区别：

* 只发送一次 HEAD 请求，**不跟随跳转**；3xx 时原样返回 ``Location``；
* 每次探测都重新解析域名，并对本次 DNS 返回的 *全部* 地址做 IPv4 CIDR
  白名单校验，全部获准才开始连接；
* 允许复用空闲连接，但必须同时满足：
  1. 与目标同源（scheme + hostname + port）；
  2. 连接的实际对端 IP 仍在 **本次探测** 的获准地址集合中。
* 新连接同样只连接本次获准的地址；HTTPS 复用/新建均按原域名校验证书；
* 一条连接同一时刻只服务一次探测（取用后即从池中移除，独占使用）；
* 仅在“收齐最终响应头”且响应允许保活时归还连接池；
* 读写失败、超时或取消时关闭连接；一旦请求可能已经发出，失败后
  **绝不向其他地址补发**。
"""

from __future__ import annotations

import asyncio
import ipaddress
from dataclasses import asdict, dataclass, field
from urllib.parse import urlsplit

from .connection import TlsInfo, build_ssl_context, open_tcp, start_tls
from .connection_pool import (
    IdleConnectionPool,
    PooledConnection,
    peer_ip_from_writer,
)
from .dns_client import DnsError, DnsResolver
from .policy import AddressPolicy, PolicyError, is_ip_literal, parse_target

DEFAULT_PORTS = {"http": 80, "https": 443}
REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
MAX_HEADER_BYTES = 64 * 1024


@dataclass
class HeadReport:
    url: str
    scheme: str = ""
    hostname: str = ""
    port: int = 0
    resolved_addresses: list[str] = field(default_factory=list)
    approved_addresses: list[str] = field(default_factory=list)
    connected_peer: str | None = None
    connection_reused: bool = False
    connection_kept_alive: bool = False
    tls: dict | None = None
    request_sent: bool = False
    status_code: int | None = None
    reason: str | None = None
    location: str | None = None
    outcome: str = "pending"  # ok | redirected | blocked | error
    reject_reason: str | None = None
    error: str | None = None

    def mark_blocked(self, reason: str) -> None:
        self.outcome = "blocked"
        self.reject_reason = reason
        self.reason = reason

    def mark_error(self, message: str) -> None:
        self.outcome = "error"
        self.error = message
        self.reason = message


class HeadProber:
    def __init__(
        self,
        policy: AddressPolicy,
        resolver: DnsResolver,
        pool: IdleConnectionPool,
        ca_bundle: str | None = None,
        connect_timeout: float = 5.0,
        read_timeout: float = 10.0,
        tls_timeout: float = 8.0,
        max_header_bytes: int = MAX_HEADER_BYTES,
    ) -> None:
        self._policy = policy
        self._resolver = resolver
        self._pool = pool
        self._ssl = build_ssl_context(ca_bundle)
        self._connect_timeout = connect_timeout
        self._read_timeout = read_timeout
        self._tls_timeout = tls_timeout
        self._max_header_bytes = max_header_bytes

    async def probe(self, url: str) -> HeadReport:
        report = HeadReport(url=url)

        # 1) URL 静态校验（不产生任何流量）
        try:
            scheme, host, port, _user, _raw = parse_target(url)
        except PolicyError as exc:
            report.mark_blocked(str(exc))
            return report
        report.scheme = scheme
        report.hostname = host
        report.port = port or DEFAULT_PORTS[scheme]

        # 2) 每次探测都重新解析，并对完整地址列表做全或无白名单校验
        try:
            if is_ip_literal(host):
                resolved = [host]
            else:
                resolved = await self._resolver.resolve_a(host)
            report.resolved_addresses = list(resolved)
            approved = self._policy.check_resolved(resolved)
            report.approved_addresses = [str(ip) for ip in approved]
        except (PolicyError, DnsError) as exc:
            report.mark_blocked(str(exc))
            return report

        # 3) 优先复用：同源 + 实际对端在本次获准地址中
        pooled = self._pool.acquire(scheme, host, report.port, approved)
        if pooled is not None:
            report.connection_reused = True
            report.connected_peer = pooled.peer
            report.tls = asdict(pooled.tls) if pooled.tls else None
            await self._exchange(report, pooled, url)
            return report

        # 4) 新建连接：只尝试本次获准的地址；连接阶段失败可换下一个
        #    已获准地址，但请求一旦可能发出就不再补发。
        last_err: str | None = None
        for ip in approved:
            conn, err = await self._connect(ip, scheme, host, report.port, approved)
            if conn is None:
                last_err = err
                continue
            report.connected_peer = conn.peer
            report.tls = asdict(conn.tls) if conn.tls else None
            report.error = None
            await self._exchange(report, conn, url)
            return report

        report.mark_error(
            f"全部已批准地址连接失败（未尝试任何未获准地址）: {last_err}"
        )
        return report

    # ------------------------------------------------------------- 建连
    async def _connect(
        self,
        ip: ipaddress.IPv4Address,
        scheme: str,
        host: str,
        port: int,
        approved: list[ipaddress.IPv4Address],
    ) -> tuple[PooledConnection | None, str | None]:
        try:
            reader, writer, _peer = await open_tcp(ip, port, self._connect_timeout)
        except PolicyError as exc:
            return None, str(exc)

        tls_info: TlsInfo | None = None
        try:
            if scheme == "https":
                reader, writer, tls_info = await start_tls(
                    writer, reader, host, self._ssl, self._tls_timeout
                )
        except (PolicyError, asyncio.CancelledError) as exc:
            _close(writer)
            if isinstance(exc, asyncio.CancelledError):
                raise
            return None, str(exc)
        except BaseException:
            _close(writer)
            raise

        peer_info = peer_ip_from_writer(writer)
        if peer_info is None:
            _close(writer)
            return None, "无法确认连接的实际对端 IPv4 地址，拒绝使用"
        peer_str, peer_ip = peer_info
        if peer_ip not in approved or peer_ip != ip:
            # 实际对端不是本次获准并指定的地址：不做任何请求
            _close(writer)
            return None, (
                f"实际对端 {peer_str} 与本次获准地址 {ip} 不一致，拒绝使用"
            )
        conn = PooledConnection(
            reader=reader,
            writer=writer,
            scheme=scheme,
            hostname=host,
            port=port,
            peer_ip=peer_ip,
            tls=tls_info,
        )
        return conn, None

    # --------------------------------------------------------- 一次请求
    async def _exchange(
        self, report: HeadReport, conn: PooledConnection, url: str
    ) -> None:
        payload = _build_head_request(url, report.hostname, report.port)
        try:
            conn.writer.write(payload)
            # 从调用 write 起，请求就可能已经发出；此后任何失败都不补发
            report.request_sent = True
            await asyncio.wait_for(
                conn.writer.drain(), timeout=self._read_timeout
            )
            response = await asyncio.wait_for(
                self._read_headers(conn.reader), timeout=self._read_timeout
            )
        except asyncio.CancelledError:
            # 取消：立即关闭，绝不把半途连接放回池中
            self._pool.discard(conn)
            raise
        except asyncio.TimeoutError:
            self._pool.discard(conn)
            report.mark_error(self._failure_message(report, "读取响应超时"))
            return
        except (PolicyError, OSError) as exc:
            self._pool.discard(conn)
            report.mark_error(self._failure_message(report, str(exc)))
            return
        except Exception as exc:  # 防御性兜底：任何异常都关闭连接
            self._pool.discard(conn)
            report.mark_error(self._failure_message(report, f"连接读写错误: {exc}"))
            return

        report.status_code = response["status"]
        report.reason = response["reason"]
        report.location = response["headers"].get("location")
        if report.status_code in REDIRECT_STATUSES:
            report.outcome = "redirected"
        else:
            report.outcome = "ok"

        # 只有收齐最终响应头、且响应明确允许保活、且没有多余字节
        # （例如 HEAD 却收到 body）时才归还连接池。
        if response["keep_alive"] and not _has_buffered_data(conn.reader):
            if self._pool.release(conn):
                report.connection_kept_alive = True
                return
            # release 返回 False 表示连接已失效，池已负责关闭
            return
        self._pool.discard(conn)

    def _failure_message(self, report: HeadReport, detail: str) -> str:
        if report.connection_reused:
            return (
                f"复用的空闲连接读写失败，请求可能已发出，按策略不补发: {detail}"
            )
        return f"连接读写失败，请求可能已发出，按策略不补发: {detail}"

    async def _read_headers(self, reader: asyncio.StreamReader) -> dict:
        """读到最终响应头（跳过 1xx 中间响应）。"""
        while True:
            status, version, reason, headers = await self._read_one_headers(reader)
            if 100 <= status < 200 and status != 101:
                # 1xx 仅为中间响应，继续等待最终响应头
                continue
            break
        connection_tokens = {
            token.strip().lower()
            for token in headers.get("connection", "").split(",")
            if token.strip()
        }
        if status == 101:  # 协议已切换，不再是可复用的 HTTP 连接
            keep_alive = False
        elif version == "1.0":
            keep_alive = "keep-alive" in connection_tokens and (
                "close" not in connection_tokens
            )
        else:
            keep_alive = "close" not in connection_tokens

        return {
            "status": status,
            "reason": reason,
            "headers": headers,
            "keep_alive": keep_alive,
        }

    async def _read_one_headers(
        self, reader: asyncio.StreamReader
    ) -> tuple[int, str, str, dict[str, str]]:
        blob = bytearray()
        while b"\r\n\r\n" not in blob:
            chunk = await reader.read(1)
            if not chunk:
                raise PolicyError("对端在响应头完成前关闭连接")
            blob.extend(chunk)
            if len(blob) > self._max_header_bytes:
                raise PolicyError("响应头部超过大小上限")
        head = bytes(blob).removesuffix(b"\r\n\r\n")
        text = head.decode("iso-8859-1")
        lines = text.split("\r\n")
        status_line = lines[0]
        if not status_line.startswith("HTTP/"):
            raise PolicyError(f"非法 HTTP 响应行: {status_line[:80]!r}")
        try:
            proto, rest = status_line.split(" ", 1)
            status_text, reason = rest.split(" ", 1) if " " in rest else (rest, "")
            status = int(status_text)
        except (IndexError, ValueError) as exc:
            raise PolicyError(f"无法解析状态行: {status_line[:80]!r}") from exc
        version = proto[len("HTTP/"):]

        headers: dict[str, str] = {}
        for line in lines[1:]:
            if not line or ":" not in line:
                continue
            key, value = line.split(":", 1)
            headers[key.strip().lower()] = value.strip()
        return status, version, reason, headers


def _build_head_request(url: str, host: str, port: int) -> bytes:
    parts = urlsplit(url)
    path = parts.path or "/"
    if parts.query:
        path = f"{path}?{parts.query}"
    scheme = parts.scheme.lower()
    default_port = DEFAULT_PORTS.get(scheme)
    authority = host if port == default_port else f"{host}:{port}"
    return (
        f"HEAD {path} HTTP/1.1\r\n"
        f"Host: {authority}\r\n"
        "User-Agent: egress-probe/1.0\r\n"
        "Accept: */*\r\n"
        "Connection: keep-alive\r\n"
        "\r\n"
    ).encode("ascii", errors="replace")


def _has_buffered_data(reader: asyncio.StreamReader) -> bool:
    """响应头之后是否还有已到达的数据（意味着连接不宜复用）。"""
    buffer = getattr(reader, "_buffer", None)
    if buffer is None:
        return False
    try:
        return len(buffer) > 0
    except TypeError:
        return False


def _close(writer: asyncio.StreamWriter) -> None:
    try:
        writer.close()
    except Exception:
        pass
