"""HTTP/HTTPS keep-alive 空闲连接池。

需求约束：
* 每进程最多保留 8 条空闲连接；
* 每条连接最多空闲 15 秒（到点主动关闭）；
* 只有“收齐最终响应头且允许保活”的连接才会被放回池中；
* 连接在池中时是空闲的，一旦被取出就只服务于一次探测，
  因此同一条连接不会同时处理两次探测；
* 复用前必须同时满足：目标同源（scheme/host/port）且连接的实际
  对端 IP 仍在 *本次探测* 的获准地址集合内。

池本身不做任何 DNS 解析，也不参与白名单决策；它只是保存已经通过
策略校验、并且仍然指向获准地址的连接。
"""

from __future__ import annotations

import asyncio
import ipaddress
from dataclasses import dataclass, field

from .connection import TlsInfo

MAX_IDLE_PER_PROCESS = 8
IDLE_TIMEOUT_SECONDS = 15.0

Origin = tuple[str, str, int]


@dataclass
class PooledConnection:
    """一条已建立（对 HTTPS 而言已完成 TLS 握手）的连接。"""

    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
    scheme: str
    hostname: str
    port: int
    peer_ip: ipaddress.IPv4Address
    tls: TlsInfo | None = None
    idle_since: float | None = None
    # 取出后置 True，归还/丢弃后置 False：确保一条连接同一时刻
    # 只被一次探测独占使用。
    busy: bool = False
    _timer: asyncio.TimerHandle | None = field(default=None, repr=False)

    @property
    def origin(self) -> Origin:
        return (self.scheme, self.hostname, self.port)

    @property
    def peer(self) -> str:
        return f"{self.peer_ip}:{self.port}"


def peer_ip_from_writer(
    writer: asyncio.StreamWriter,
) -> tuple[str, ipaddress.IPv4Address] | None:
    """读取 socket 的真实对端地址；非 IPv4 或不可用时返回 None。"""
    info = writer.get_extra_info("peername")
    if not info:
        return None
    try:
        host = str(info[0])
        port = int(info[1])
        ip = ipaddress.ip_address(host)
    except (TypeError, ValueError, IndexError):
        return None
    if ip.version != 4:
        return None
    return f"{ip}:{port}", ip


class IdleConnectionPool:
    def __init__(
        self,
        max_idle: int = MAX_IDLE_PER_PROCESS,
        idle_timeout: float = IDLE_TIMEOUT_SECONDS,
    ) -> None:
        if max_idle < 0:
            raise ValueError("max_idle 不能为负")
        if idle_timeout <= 0:
            raise ValueError("idle_timeout 必须大于 0")
        self._max_idle = max_idle
        self._idle_timeout = idle_timeout
        self._idle: dict[Origin, list[PooledConnection]] = {}
        self._closed = False

    # ------------------------------------------------------------- 状态查询
    @property
    def idle_count(self) -> int:
        return sum(len(entries) for entries in self._idle.values())

    @property
    def max_idle(self) -> int:
        return self._max_idle

    @property
    def idle_timeout(self) -> float:
        return self._idle_timeout

    def stats(self) -> dict:
        return {
            "idle_connections": self.idle_count,
            "max_idle_connections": self._max_idle,
            "idle_timeout_seconds": self._idle_timeout,
        }

    # ----------------------------------------------------------------- 取用
    def acquire(
        self,
        scheme: str,
        hostname: str,
        port: int,
        approved_peers: list[ipaddress.IPv4Address] | set[ipaddress.IPv4Address],
    ) -> PooledConnection | None:
        """取出同源且实际对端仍在本次获准地址中的空闲连接。

        返回的连接已从池中移除，调用方对它拥有独占使用权。
        """
        if self._closed:
            return None
        self._prune_expired()
        key = (scheme, hostname, port)
        entries = self._idle.get(key)
        if not entries:
            return None
        approved = set(approved_peers)
        for entry in list(entries):
            if entry.busy:
                continue
            if entry.peer_ip not in approved:
                # 同源但本次 DNS 未返回该地址：绝不复用
                continue
            # 以 socket 的真实对端为准再次确认（防止记录与实际不符）
            live_peer = peer_ip_from_writer(entry.writer)
            if live_peer is None or live_peer[1] not in approved:
                self._remove(entry)
                _close_writer(entry)
                continue
            if self._is_dead(entry) or _has_stray_data(entry):
                self._remove(entry)
                _close_writer(entry)
                continue
            self._remove(entry)
            entry.busy = True
            return entry
        return None

    # ----------------------------------------------------------------- 归还
    def release(self, conn: PooledConnection) -> bool:
        """把连接放回池中；不满足保活条件时直接关闭并返回 False。"""
        if conn.busy:
            # 归还后不再处于“被本次探测独占”状态
            conn.busy = False
        if self._closed or self._is_dead(conn):
            _close_writer(conn)
            return False
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:  # 事件循环已退出，无法安全复用
            _close_writer(conn)
            return False
        conn.idle_since = loop.time()
        conn._timer = loop.call_later(self._idle_timeout, self._expire, conn)
        self._idle.setdefault(conn.origin, []).append(conn)
        self._enforce_capacity()
        # 容量为 0 或刚归还就被挤出时，连接已被关闭，不能报告为“保留”
        return conn.idle_since is not None

    def discard(self, conn: PooledConnection) -> None:
        """关闭并丢弃连接（读写失败、超时、取消等路径使用）。"""
        conn.busy = False
        if conn.idle_since is not None:
            self._remove(conn)
        _close_writer(conn)

    async def aclose(self) -> None:
        self._closed = True
        for entries in list(self._idle.values()):
            for entry in list(entries):
                self._remove(entry)
                _close_writer(entry)
        self._idle.clear()

    # --------------------------------------------------------------- 内部
    def _is_dead(self, conn: PooledConnection) -> bool:
        try:
            if conn.writer.is_closing():
                return True
            if conn.reader.at_eof():
                return True
            return conn.reader.exception() is not None
        except Exception:  # 已损坏的流对象一律视为不可用
            return True

    def _remove(self, conn: PooledConnection) -> None:
        entries = self._idle.get(conn.origin)
        if entries and conn in entries:
            entries.remove(conn)
        if entries is not None and not entries:
            self._idle.pop(conn.origin, None)
        if conn._timer is not None:
            conn._timer.cancel()
            conn._timer = None
        conn.idle_since = None

    def _expire(self, conn: PooledConnection) -> None:
        if conn.idle_since is None:
            return
        self._remove(conn)
        _close_writer(conn)

    def _prune_expired(self) -> None:
        try:
            now = asyncio.get_running_loop().time()
        except RuntimeError:
            return
        for entries in list(self._idle.values()):
            for entry in list(entries):
                if entry.idle_since is not None and (
                    now - entry.idle_since >= self._idle_timeout
                ):
                    self._remove(entry)
                    _close_writer(entry)

    def _enforce_capacity(self) -> None:
        while self.idle_count > self._max_idle:
            # 关闭空闲时间最久的一条，保留较新的连接
            oldest: PooledConnection | None = None
            for entries in self._idle.values():
                for entry in entries:
                    if oldest is None or (
                        (entry.idle_since or 0.0) < (oldest.idle_since or 0.0)
                    ):
                        oldest = entry
            if oldest is None:
                return
            self._remove(oldest)
            _close_writer(oldest)


def _close_writer(conn: PooledConnection) -> None:
    try:
        conn.writer.close()
    except Exception:
        pass


def _has_stray_data(conn: PooledConnection) -> bool:
    """池中空闲连接上是否残留了未被读取的数据。

    残留数据意味着对端在本该空闲的期间又发送了内容，连接状态不可信，
    不得再用于下一次探测。
    """
    buffer = getattr(conn.reader, "_buffer", None)
    if buffer is None:
        return False
    try:
        return len(buffer) > 0
    except TypeError:
        return True
