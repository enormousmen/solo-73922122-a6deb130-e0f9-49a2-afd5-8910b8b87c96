"""单跳 HEAD 探测与空闲连接复用测试（真实 TCP / TLS / DNS）。

覆盖需求关键点：
* 每次探测重新解析并全量校验白名单；
* 同源 + 实际对端仍在本次获准地址中才复用；换址后重新建连；
* 响应头收齐且允许保活才归还连接池；失败/超时/取消关闭连接；
* 请求可能已发出时失败不补发；
* 每进程最多 8 条空闲连接，每条最多空闲 15 秒；
* 跳转只返回 Location，不跟随。
"""

from __future__ import annotations

import asyncio
import ssl

import pytest

from app.probe.connection_pool import (
    IDLE_TIMEOUT_SECONDS,
    MAX_IDLE_PER_PROCESS,
    IdleConnectionPool,
)
from app.probe.dns_client import DnsResolver
from app.probe.head_probe import HeadProber
from app.probe.policy import AddressPolicy


class KeepAliveHttpServer:
    """支持 keep-alive 的测试服务器，按 Host+path 返回预置响应。

    记录每次请求及其所在 TCP 连接编号，便于断言连接是否被复用。
    """

    def __init__(self, ssl_ctx: ssl.SSLContext | None = None) -> None:
        self.routes: dict[tuple[str, str], tuple[int, list[tuple[str, str]], str,
                                                bool]] = {}
        self.requests: list[dict] = []
        self.connections = 0
        self.ssl_ctx = ssl_ctx
        self._server: asyncio.base_events.Server | None = None
        self.port = 0
        self._handlers: set[asyncio.Task] = set()

    def route(self, host: str, path: str, status: int = 200,
              headers: list[tuple[str, str]] | None = None,
              body: str = "ok", keep_alive: bool = True) -> None:
        self.routes[(host.lower(), path)] = (
            status, headers or [], body, keep_alive
        )

    async def _handle(self, reader, writer) -> None:  # noqa: ANN001
        self.connections += 1
        conn_id = self.connections
        try:
            while True:
                request_line = await reader.readline()
                if not request_line:
                    break
                method, path, _ = request_line.decode().split(" ", 2)
                headers: dict[str, str] = {}
                while True:
                    line = await reader.readline()
                    if line in (b"\r\n", b"\n", b""):
                        break
                    k, v = line.decode().split(":", 1)
                    headers[k.strip().lower()] = v.strip()
                host = headers.get("host", "").split(":")[0].lower()
                self.requests.append(
                    {
                        "method": method,
                        "host": host,
                        "path": path,
                        "conn": conn_id,
                        "connection": headers.get("connection"),
                    }
                )
                status, extra, body, keep_alive = self.routes.get(
                    (host, path), (404, [], "not found", True)
                )
                resp = [
                    f"HTTP/1.1 {status} X\r\n",
                    f"Content-Length: {len(body)}\r\n",
                ]
                for k, v in extra:
                    resp.append(f"{k}: {v}\r\n")
                if not keep_alive:
                    resp.append("Connection: close\r\n")
                resp.append("\r\n")
                if method != "HEAD":
                    resp.append(body)
                writer.write("".join(resp).encode())
                await writer.drain()
                if not keep_alive:
                    break
        except (ConnectionError, ssl.SSLError, ValueError):
            pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except (OSError, ssl.SSLError):
                pass

    async def start(self) -> int:
        # 绑定 0.0.0.0，使 127.0.0.1 / 127.0.0.2 都能命中同一监听（换址演示）
        self._server = await asyncio.start_server(
            self._handle, "0.0.0.0", 0, ssl=self.ssl_ctx
        )
        self.port = self._server.sockets[0].getsockname()[1]
        return self.port

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()

    def hosts_on_connection(self, conn_id: int) -> list[str]:
        return [r["host"] for r in self.requests if r["conn"] == conn_id]


@pytest.fixture()
def make_head_prober(fake_dns, demo_certs):
    _cert, _key, cafile = demo_certs

    def _factory(allowed=("127.0.0.0/24",), max_idle: int = 8,
                 idle_timeout: float = 15.0,
                 read_timeout: float = 5.0) -> tuple[HeadProber, IdleConnectionPool]:
        policy = AddressPolicy.from_cidrs(list(allowed))
        resolver = DnsResolver("127.0.0.1", port=fake_dns.port, timeout=2.0, retries=0)
        pool = IdleConnectionPool(max_idle=max_idle, idle_timeout=idle_timeout)
        prober = HeadProber(
            policy=policy,
            resolver=resolver,
            pool=pool,
            ca_bundle=str(cafile),
            connect_timeout=3.0,
            read_timeout=read_timeout,
            tls_timeout=5.0,
        )
        return prober, pool

    return _factory


@pytest.fixture()
async def keepalive_server():
    srv = KeepAliveHttpServer()
    await srv.start()
    try:
        yield srv
    finally:
        await srv.stop()


@pytest.fixture()
async def keepalive_https_server(demo_certs):
    certfile, keyfile, _cafile = demo_certs
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(certfile), str(keyfile))
    srv = KeepAliveHttpServer(ssl_ctx=ctx)
    await srv.start()
    try:
        yield srv
    finally:
        await srv.stop()


class TestHeadProbeBasics:
    async def test_single_hop_head_ok(
        self, fake_dns, keepalive_server, make_head_prober
    ):
        fake_dns.set_zones({"h.test": ["127.0.0.1"]})
        keepalive_server.route("h.test", "/ping")
        prober, _pool = make_head_prober()

        report = await prober.probe(f"http://h.test:{keepalive_server.port}/ping")

        assert report.outcome == "ok"
        assert report.status_code == 200
        assert report.request_sent is True
        assert report.connected_peer == f"127.0.0.1:{keepalive_server.port}"
        assert report.connection_reused is False
        assert report.connection_kept_alive is True
        assert keepalive_server.requests[-1]["method"] == "HEAD"
        assert keepalive_server.requests[-1]["connection"] == "keep-alive"

    async def test_reuses_same_origin_connection(
        self, fake_dns, keepalive_server, make_head_prober
    ):
        fake_dns.set_zones({"h.test": ["127.0.0.1"]})
        keepalive_server.route("h.test", "/a")
        keepalive_server.route("h.test", "/b")
        prober, pool = make_head_prober()

        first = await prober.probe(f"http://h.test:{keepalive_server.port}/a")
        second = await prober.probe(f"http://h.test:{keepalive_server.port}/b")

        assert first.connection_reused is False
        assert second.connection_reused is True
        assert first.connected_peer == second.connected_peer
        assert keepalive_server.connections == 1
        assert [r["path"] for r in keepalive_server.requests] == ["/a", "/b"]
        assert pool.idle_count == 1

    async def test_dns_switch_to_new_address_reconnects(
        self, fake_dns, keepalive_server, make_head_prober
    ):
        # 两个“获准目标”：同一监听上的 127.0.0.1 与 127.0.0.2
        fake_dns.set_zones({"switch.test": ["127.0.0.1"]})
        keepalive_server.route("switch.test", "/")
        prober, pool = make_head_prober()

        first = await prober.probe(f"http://switch.test:{keepalive_server.port}/")
        # 本地 DNS 热切换：同名域名换到另一个获准地址
        fake_dns.set_zones({"switch.test": ["127.0.0.2"]})
        second = await prober.probe(f"http://switch.test:{keepalive_server.port}/")

        assert first.connected_peer.startswith("127.0.0.1:")
        assert second.connected_peer.startswith("127.0.0.2:")
        assert second.connection_reused is False
        assert keepalive_server.connections == 2
        # 旧地址的空闲连接仍留在池中（仍属池的容量），但不会被错用
        assert all(
            r["conn"] == 1 for r in keepalive_server.requests[:1]
        )
        assert pool.idle_count == 2

    async def test_same_address_different_origin_not_reused(
        self, fake_dns, keepalive_server, make_head_prober
    ):
        fake_dns.set_zones({
            "a.test": ["127.0.0.1"],
            "b.test": ["127.0.0.1"],
        })
        keepalive_server.route("a.test", "/")
        keepalive_server.route("b.test", "/")
        prober, _pool = make_head_prober()

        await prober.probe(f"http://a.test:{keepalive_server.port}/")
        second = await prober.probe(f"http://b.test:{keepalive_server.port}/")

        assert second.connection_reused is False
        assert keepalive_server.connections == 2

    async def test_different_port_not_reused(
        self, fake_dns, keepalive_server, make_head_prober
    ):
        fake_dns.set_zones({"p.test": ["127.0.0.1"]})
        keepalive_server.route("p.test", "/")
        prober, _pool = make_head_prober()

        await prober.probe(f"http://p.test:{keepalive_server.port}/")
        second = await prober.probe(
            f"http://p.test:{keepalive_server.port + 1}/"
        )
        # 端口 +1 无服务：必须尝试新连接而不是复用其它端口的连接
        assert second.connection_reused is False
        assert second.outcome == "error"

    async def test_redirect_returns_location_without_following(
        self, fake_dns, keepalive_server, make_head_prober
    ):
        fake_dns.set_zones({
            "r.test": ["127.0.0.1"],
            "target.test": ["127.0.0.1"],
        })
        keepalive_server.route(
            "r.test", "/go", status=302,
            headers=[("Location", f"http://target.test:{keepalive_server.port}/x")],
        )
        keepalive_server.route("target.test", "/x")
        prober, pool = make_head_prober()

        report = await prober.probe(f"http://r.test:{keepalive_server.port}/go")

        assert report.outcome == "redirected"
        assert report.status_code == 302
        assert report.location.endswith("/x")
        assert report.connection_kept_alive is True
        assert pool.idle_count == 1
        # 没有向跳转目标发请求
        assert all(r["host"] != "target.test" for r in keepalive_server.requests)

    async def test_connection_close_not_pooled(
        self, fake_dns, keepalive_server, make_head_prober
    ):
        fake_dns.set_zones({"c.test": ["127.0.0.1"]})
        keepalive_server.route("c.test", "/", keep_alive=False)
        prober, pool = make_head_prober()

        report = await prober.probe(f"http://c.test:{keepalive_server.port}/")

        assert report.outcome == "ok"
        assert report.connection_kept_alive is False
        assert pool.idle_count == 0

    async def test_blocked_target_receives_no_request(
        self, fake_dns, keepalive_server, make_head_prober
    ):
        fake_dns.set_zones({"bad.test": ["8.8.8.8"]})
        keepalive_server.route("bad.test", "/")
        prober, pool = make_head_prober(allowed=("127.0.0.0/24",))
        before = len(keepalive_server.requests)

        report = await prober.probe(f"http://bad.test:{keepalive_server.port}/")

        assert report.outcome == "blocked"
        assert report.request_sent is False
        assert report.connected_peer is None
        assert len(keepalive_server.requests) == before
        assert pool.idle_count == 0

    async def test_mixed_resolution_rejected_wholesale(
        self, fake_dns, keepalive_server, make_head_prober
    ):
        fake_dns.set_zones({"mix.test": ["127.0.0.1", "8.8.8.8"]})
        prober, _pool = make_head_prober()

        report = await prober.probe(f"http://mix.test:{keepalive_server.port}/")

        assert report.outcome == "blocked"
        assert "整体拒绝" in report.reject_reason
        assert report.request_sent is False


class TestHeadProbeTls:
    async def test_https_verified_and_reused(
        self, fake_dns, keepalive_https_server, make_head_prober
    ):
        fake_dns.set_zones({"https.allowed.demo.test": ["127.0.0.1"]})
        keepalive_https_server.route("https.allowed.demo.test", "/a")
        keepalive_https_server.route("https.allowed.demo.test", "/b")
        prober, _pool = make_head_prober()

        first = await prober.probe(
            f"https://https.allowed.demo.test:{keepalive_https_server.port}/a"
        )
        second = await prober.probe(
            f"https://https.allowed.demo.test:{keepalive_https_server.port}/b"
        )

        assert first.outcome == "ok"
        assert first.tls is not None
        assert "https.allowed.demo.test" in first.tls["san"]
        assert second.connection_reused is True
        assert keepalive_https_server.connections == 1  # 只握手一次

    async def test_https_hostname_mismatch_not_pooled(
        self, fake_dns, keepalive_https_server, make_head_prober
    ):
        fake_dns.set_zones({"other.test": ["127.0.0.1"]})
        prober, pool = make_head_prober()

        report = await prober.probe(
            f"https://other.test:{keepalive_https_server.port}/"
        )

        assert report.outcome == "error"
        assert "证书校验失败" in report.error
        assert pool.idle_count == 0


class TestFailureHandling:
    async def test_timeout_closes_connection_and_does_not_resend(
        self, fake_dns, make_head_prober
    ):
        accepted = 0

        async def silent(reader, writer):  # noqa: ANN001
            nonlocal accepted
            accepted += 1
            # 读到请求后什么都不回，触发读超时
            await reader.read(4096)
            await asyncio.sleep(30)
            writer.close()

        server = await asyncio.start_server(silent, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        fake_dns.set_zones({"slow.test": ["127.0.0.1"]})
        prober, pool = make_head_prober(read_timeout=0.3)
        try:
            report = await prober.probe(f"http://slow.test:{port}/")
        finally:
            server.close()
            await server.wait_closed()

        assert report.outcome == "error"
        assert "不补发" in report.error
        assert report.request_sent is True
        assert accepted == 1  # 请求可能已发出：没有重试/补发
        assert pool.idle_count == 0

    async def test_cancel_closes_connection(
        self, fake_dns, make_head_prober
    ):
        release = asyncio.Event()
        accepted = 0

        async def hang(reader, writer):  # noqa: ANN001
            nonlocal accepted
            accepted += 1
            await reader.read(4096)
            await release.wait()
            writer.close()

        server = await asyncio.start_server(hang, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        fake_dns.set_zones({"hang.test": ["127.0.0.1"]})
        prober, pool = make_head_prober(read_timeout=30.0)
        try:
            task = asyncio.create_task(prober.probe(f"http://hang.test:{port}/"))
            await asyncio.sleep(0.2)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
            await asyncio.sleep(0)
        finally:
            release.set()
            server.close()
            await server.wait_closed()

        assert accepted == 1
        assert pool.idle_count == 0

    async def test_reused_connection_failure_closes_and_no_resend(
        self, fake_dns, make_head_prober
    ):
        # 第一跳正常并留存连接；服务器随即断开；第二次复用该连接发起
        # 请求后失败，不得补发新连接。
        state = {"conn": 0}

        async def handler(reader, writer):  # noqa: ANN001
            state["conn"] += 1
            n = state["conn"]
            first_request = True
            while True:
                line = await reader.readline()
                if not line:
                    return
                while True:
                    h = await reader.readline()
                    if h in (b"\r\n", b"\n", b""):
                        break
                if not first_request:
                    # 第二次请求（复用连接）收到后直接断开，不返回响应
                    writer.close()
                    return
                first_request = False
                body = "ok"
                writer.write(
                    (
                        "HTTP/1.1 200 OK\r\n"
                        f"Content-Length: {len(body)}\r\n\r\n"
                    ).encode()
                )
                await writer.drain()

        server = await asyncio.start_server(handler, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        fake_dns.set_zones({"flaky.test": ["127.0.0.1"]})
        prober, pool = make_head_prober(read_timeout=1.0)
        try:
            first = await prober.probe(f"http://flaky.test:{port}/")
            assert first.connection_kept_alive is True
            await asyncio.sleep(0.1)  # 让服务端关闭到达客户端
            second = await prober.probe(f"http://flaky.test:{port}/")
        finally:
            server.close()
            await server.wait_closed()

        assert second.outcome == "error"
        assert "不补发" in second.error
        assert state["conn"] == 1  # 没有新建连接补发
        assert pool.idle_count == 0


class TestPoolLimits:
    def test_pool_defaults_match_requirements(self):
        pool = IdleConnectionPool()
        assert pool.max_idle == 8 == MAX_IDLE_PER_PROCESS
        assert pool.idle_timeout == 15.0 == IDLE_TIMEOUT_SECONDS

    def test_config_rejects_over_limit_pool_settings(self, monkeypatch):
        from app.probe.config import load_settings

        base = {
            "ALLOWED_CIDRS": "127.0.0.1/32",
            "MAX_IDLE_CONNECTIONS": "8",
            "IDLE_TIMEOUT": "15",
        }
        for key, value in base.items():
            monkeypatch.setenv(key, value)
        settings = load_settings()
        assert settings.max_idle_connections == 8
        assert settings.idle_timeout == 15.0

        monkeypatch.setenv("MAX_IDLE_CONNECTIONS", "9")
        with pytest.raises(SystemExit, match="0..8"):
            load_settings()

        monkeypatch.setenv("MAX_IDLE_CONNECTIONS", "8")
        monkeypatch.setenv("IDLE_TIMEOUT", "15.1")
        with pytest.raises(SystemExit, match="15"):
            load_settings()

        monkeypatch.setenv("IDLE_TIMEOUT", "0")
        with pytest.raises(SystemExit):
            load_settings()

    async def test_capacity_capped_at_max_idle(
        self, fake_dns, keepalive_server, make_head_prober
    ):
        # 通过 8 个不同端口打开 8 条连接需要多监听；改用不同 hostname 同端口，
        # 每条独立建连（同源不同 host 不复用）。
        names = [f"cap{i}.test" for i in range(10)]
        fake_dns.set_zones({n: ["127.0.0.1"] for n in names})
        for n in names:
            keepalive_server.route(n, "/")
        prober, pool = make_head_prober(max_idle=8)

        for n in names:
            report = await prober.probe(f"http://{n}:{keepalive_server.port}/")
            assert report.connection_reused is False
            assert report.connection_kept_alive is True

        assert pool.idle_count == 8

    async def test_idle_connection_expires(
        self, fake_dns, keepalive_server, make_head_prober
    ):
        fake_dns.set_zones({"idle.test": ["127.0.0.1"]})
        keepalive_server.route("idle.test", "/")
        prober, pool = make_head_prober(idle_timeout=0.2)

        first = await prober.probe(f"http://idle.test:{keepalive_server.port}/")
        assert first.connection_kept_alive is True
        assert pool.idle_count == 1
        await asyncio.sleep(0.35)
        assert pool.idle_count == 0  # 定时器主动关闭

        second = await prober.probe(f"http://idle.test:{keepalive_server.port}/")
        assert second.connection_reused is False
        assert keepalive_server.connections == 2

    async def test_zero_idle_capacity_closes_immediately(
        self, fake_dns, keepalive_server, make_head_prober
    ):
        fake_dns.set_zones({"zero.test": ["127.0.0.1"]})
        keepalive_server.route("zero.test", "/")
        prober, pool = make_head_prober(max_idle=0)

        report = await prober.probe(f"http://zero.test:{keepalive_server.port}/")

        assert report.outcome == "ok"
        assert report.connection_kept_alive is False
        assert pool.idle_count == 0

    async def test_reuse_when_dns_returns_multiple_approved_addresses(
        self, fake_dns, keepalive_server, make_head_prober
    ):
        # 本次解析返回两个获准地址，池中对端属于其中之一 -> 允许复用
        fake_dns.set_zones({"multi.test": ["127.0.0.1"]})
        keepalive_server.route("multi.test", "/")
        prober, pool = make_head_prober()

        await prober.probe(f"http://multi.test:{keepalive_server.port}/")
        fake_dns.set_zones({
            "multi.test": ["127.0.0.2", "127.0.0.1"],
        })
        second = await prober.probe(f"http://multi.test:{keepalive_server.port}/")

        assert second.resolved_addresses == ["127.0.0.2", "127.0.0.1"]
        assert second.connection_reused is True
        assert second.connected_peer == f"127.0.0.1:{keepalive_server.port}"
        assert keepalive_server.connections == 1

    async def test_idle_connection_not_reused_when_peer_left_approved_set(
        self, fake_dns, keepalive_server, make_head_prober
    ):
        # 池中只有一条指向 127.0.0.1 的旧连接；本次 DNS 只返回 127.0.0.2，
        # 旧连接的对端已不在本次获准集合中，必须新建而不得复用。
        fake_dns.set_zones({"moved.test": ["127.0.0.1"]})
        keepalive_server.route("moved.test", "/")
        prober, pool = make_head_prober()

        first = await prober.probe(f"http://moved.test:{keepalive_server.port}/")
        assert first.connection_reused is False
        assert pool.idle_count == 1

        fake_dns.set_zones({"moved.test": ["127.0.0.2"]})
        second = await prober.probe(f"http://moved.test:{keepalive_server.port}/")

        assert second.connection_reused is False
        assert second.connected_peer.startswith("127.0.0.2:")
        assert keepalive_server.connections == 2
        # 旧连接仍留在池中（未被错用），新连接也入池
        assert pool.idle_count == 2
