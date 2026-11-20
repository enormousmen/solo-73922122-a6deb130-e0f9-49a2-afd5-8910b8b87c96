"""单跳 HEAD API 层测试（同一事件循环内的假 DNS + keep-alive HTTP 服务）。"""

from __future__ import annotations

import asyncio
import importlib
from contextlib import asynccontextmanager

import pytest
from fastapi.testclient import TestClient

from app.probe import dns_wire


class InLoopDns:
    def __init__(self) -> None:
        self.zones: dict[str, list[str]] = {}
        self._transport = None

    def connection_made(self, transport):  # noqa: ANN001
        self._transport = transport

    def connection_lost(self, exc) -> None:  # noqa: ANN001
        self._transport = None

    def datagram_received(self, data: bytes, addr) -> None:  # noqa: ANN001
        msg = dns_wire.parse_message(data, require_qr=False)
        q = msg.questions[0]
        if q.qname.lower() in self.zones:
            reply = dns_wire.build_response(
                msg.qid, q, answers=self.zones[q.qname.lower()]
            )
        else:
            reply = dns_wire.build_response(
                msg.qid, q, rcode=dns_wire.RCODE_NAME_ERROR
            )
        self._transport.sendto(reply, addr)


class InLoopKeepAliveHttp:
    """支持 keep-alive 的测试服务；HEAD 响应不带 body。"""

    def __init__(self) -> None:
        self.routes: dict[tuple[str, str], tuple[int, dict, str]] = {}
        self.requests: list[dict] = []
        self.connections = 0
        self._server = None
        self.port = 0

    def route(self, host, path, status=200, headers=None, body="ok"):  # noqa: ANN001
        self.routes[(host.lower(), path)] = (status, headers or {}, body)

    async def _handle(self, reader, writer):  # noqa: ANN001
        self.connections += 1
        try:
            while True:
                line = await reader.readline()
                if not line:
                    return
                method, path, _ = line.decode().split(" ", 2)
                headers: dict[str, str] = {}
                while True:
                    h = await reader.readline()
                    if h in (b"\r\n", b"\n", b""):
                        break
                    k, v = h.decode().split(":", 1)
                    headers[k.strip().lower()] = v.strip()
                host = headers.get("host", "").split(":")[0].lower()
                self.requests.append({"method": method, "host": host, "path": path})
                status, extra, body = self.routes.get((host, path), (404, {}, "nf"))
                head = [f"HTTP/1.1 {status} X\r\n",
                        f"Content-Length: {len(body)}\r\n"]
                for k, v in extra.items():
                    head.append(f"{k}: {v}\r\n")
                head.append("\r\n")
                if method != "HEAD":
                    head.append(body)
                writer.write("".join(head).encode())
                await writer.drain()
        except (ConnectionError, ValueError):
            pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except OSError:
                pass

    async def start(self) -> None:
        self._server = await asyncio.start_server(self._handle, "0.0.0.0", 0)
        self.port = self._server.sockets[0].getsockname()[1]

    async def stop(self) -> None:
        self._server.close()
        await self._server.wait_closed()


@pytest.fixture()
def head_client(monkeypatch, demo_certs):
    _cert, _key, cafile = demo_certs
    dns = InLoopDns()
    httpd = InLoopKeepAliveHttp()

    import app.probe.main as main_mod

    @asynccontextmanager
    async def test_lifespan(app):
        loop = asyncio.get_running_loop()
        transport, _ = await loop.create_datagram_endpoint(
            lambda: dns, local_addr=("127.0.0.1", 0)
        )
        dns._transport = transport
        dns_port = transport.get_extra_info("socket").getsockname()[1]
        await httpd.start()

        monkeypatch.setenv("ALLOWED_CIDRS", "127.0.0.0/24")
        monkeypatch.setenv("DNS_SERVER", "127.0.0.1")
        monkeypatch.setenv("DNS_PORT", str(dns_port))
        monkeypatch.setenv("DNS_RETRIES", "0")
        monkeypatch.setenv("DNS_TIMEOUT", "2.0")
        monkeypatch.setenv("CA_BUNDLE", str(cafile))
        monkeypatch.setenv("CONNECT_TIMEOUT", "3.0")
        monkeypatch.setenv("READ_TIMEOUT", "5.0")
        monkeypatch.setenv("TLS_TIMEOUT", "5.0")
        monkeypatch.setenv("PROBE_OVERALL_TIMEOUT", "15.0")
        monkeypatch.setenv("MAX_IDLE_CONNECTIONS", "8")
        monkeypatch.setenv("IDLE_TIMEOUT", "15")

        import app.probe.config as config_mod
        import app.probe.dns_client as dns_client_mod

        importlib.reload(config_mod)
        importlib.reload(dns_client_mod)
        importlib.reload(main_mod)
        main_mod.app.router.lifespan_context = test_lifespan
        try:
            yield
        finally:
            transport.close()
            await httpd.stop()

    main_mod.app.router.lifespan_context = test_lifespan
    dns.zones = {"head.test": ["127.0.0.1"]}
    httpd.route("head.test", "/ping")
    with TestClient(main_mod.app) as c:
        c._dns = dns
        c._http = httpd
        yield c


def test_head_probe_new_then_reused(head_client):
    port = head_client._http.port
    url = f"http://head.test:{port}/ping"

    first = head_client.post("/api/v1/probe/head", json={"url": url})
    assert first.status_code == 200
    body = first.json()
    assert body["outcome"] == "ok"
    assert body["method"] == "HEAD"
    assert body["hop"]["status_code"] == 200
    assert body["hop"]["connection_reused"] is False
    assert body["hop"]["connection_kept_alive"] is True
    assert body["hop"]["connected_peer"] == f"127.0.0.1:{port}"
    assert body["pool"]["idle_connections"] == 1

    second = head_client.post("/api/v1/probe/head", json={"url": url})
    body2 = second.json()
    assert body2["hop"]["connection_reused"] is True
    assert body2["hop"]["connected_peer"] == f"127.0.0.1:{port}"
    assert head_client._http.connections == 1
    assert [r["method"] for r in head_client._http.requests] == ["HEAD", "HEAD"]


def test_head_probe_redirect_returns_location(head_client):
    port = head_client._http.port
    head_client._http.route(
        "head.test", "/go", status=302,
        headers={"Location": f"http://head.test:{port}/final"},
    )
    head_client._http.route("head.test", "/final")

    body = head_client.post(
        "/api/v1/probe/head", json={"url": f"http://head.test:{port}/go"}
    ).json()

    assert body["outcome"] == "redirected"
    assert body["hop"]["status_code"] == 302
    assert body["hop"]["location"].endswith("/final")
    assert all(r["path"] != "/final" for r in head_client._http.requests)


def test_head_probe_dns_switch_reconnects(head_client):
    port = head_client._http.port
    url = f"http://head.test:{port}/ping"

    first = head_client.post("/api/v1/probe/head", json={"url": url}).json()
    assert first["hop"]["connected_peer"].startswith("127.0.0.1:")
    assert first["hop"]["connection_reused"] is False

    # 本地 DNS 热切换到另一个获准地址（同一监听，0.0.0.0 绑定）
    head_client._dns.zones = {"head.test": ["127.0.0.2"]}
    second = head_client.post("/api/v1/probe/head", json={"url": url}).json()
    assert second["hop"]["resolved_addresses"] == ["127.0.0.2"]
    assert second["hop"]["connected_peer"].startswith("127.0.0.2:")
    assert second["hop"]["connection_reused"] is False
    assert head_client._http.connections == 2


def test_head_probe_blocked(head_client):
    head_client._dns.zones = {"bad.test": ["8.8.8.8"]}
    body = head_client.post(
        "/api/v1/probe/head", json={"url": "http://bad.test/"}
    ).json()
    assert body["outcome"] == "blocked"
    assert body["hop"]["request_sent"] is False
    assert body["hop"]["connected_peer"] is None
    assert body["pool"]["idle_connections"] == 0


def test_head_probe_invalid_scheme_blocked(head_client):
    body = head_client.post(
        "/api/v1/probe/head", json={"url": "ftp://head.test/"}
    ).json()
    assert body["outcome"] == "blocked"
    assert body["hop"]["request_sent"] is False


def test_policy_reports_pool_limits(head_client):
    body = head_client.get("/api/v1/policy").json()
    assert body["connection_pool"]["max_idle_connections"] == 8
    assert body["connection_pool"]["idle_timeout_seconds"] == 15.0


def test_openapi_includes_head_endpoint(head_client):
    spec = head_client.get("/openapi.json").json()
    assert "/api/v1/probe/head" in spec["paths"]
    assert head_client.get("/docs").status_code == 200
