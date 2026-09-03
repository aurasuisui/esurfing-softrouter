#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
esurfing_lite.py v2 — 天翼校园(广东CDC portal) Linux 无头认证客户端

协议已在本校 portal (cdcportal/1.4.2/gd-portal-12) 上实测通过：
  1. 发现: GET 192.168.132.251 -> 302 -> 125.88.59.131:10001(返回 schoolid/domain/area)
           -> 302 -> 14.146.227.141:7001/index.cgi (页面注释里带 ticket-url/auth-url)
  2. 引导: 向 ticket.cgi 发任意内容, 服务端回 Error-Code:200 + 会话算法文件
           (001@<ticket>$<GUID>] + LZMA压缩的 .so, 见 _extract_so)
  3. 会话算法: ctypes 加载 .so, 用 Code() 编码请求 / DeCode() 解码响应,
              Algo-ID 头 = 响应里的 GUID, CDC-Checksum = MD5(编码串)小写
  4. ticket -> auth -> keep 心跳循环 -> term 下线

与官方客户端的不同: 不包含任何"共享检测"逻辑, 心跳不带 <shared>。

依赖: 仅 Python 3 标准库 + 会话 .so (由服务端动态下发, 本程序自动提取)
"""
import argparse
import ctypes
import hashlib
import http.client
import logging
import lzma
import os
import re
import signal
import socket
import struct
import sys
import time
import urllib.parse
import uuid
from pathlib import Path

log = logging.getLogger("esurfing-lite")

DEFAULT_CONF = "/etc/esurfing/lite.conf"
STATE_DIR = "/var/lib/esurfing-lite"
UA = "CCTP/Linux64/1003"
OSTAG = "linux64"
DISCOVER_HOST = "http://192.168.132.251/"


# --------------------------------------------------------------------------
# 配置
# --------------------------------------------------------------------------
def load_conf(path):
    cfg = {
        "user": None,
        "pass": None,
        "discover_host": DISCOVER_HOST,
        "schoolid": "",
        "domain": "",
        "area": "",
        "hostname": None,
        "interval": 60,
        "retry_delay": 10,
        "iface": "",
        "clientmac": "",
        "ticket_base": "",
        "ticket_params": "",
        "auth_url": "",
        "wlanacip": "",
        "wlanacname": "",
        "paip": "",
        "vlan": "",
        "iarmdst": "",
        "portal_node": "",
    }
    p = Path(path)
    if p.exists():
        for line in p.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, _, v = line.partition("=")
            k = k.strip()
            v = v.strip().strip("'").strip('"')
            if k in cfg:
                cfg[k] = v
    return cfg


def now_str():
    return time.strftime("%Y-%m-%d %H:%M:%S")


def get_client_id():
    path = Path(STATE_DIR) / "client-id"
    try:
        if path.exists():
            cid = path.read_text().strip()
            if len(cid) == 36:
                return cid
    except OSError:
        pass
    cid = str(uuid.uuid4()).upper()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(cid)
        os.chmod(path, 0o600)
    except OSError:
        pass
    return cid


def get_default_iface():
    try:
        for line in Path("/proc/net/route").read_text().splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 2 and parts[1] == "00000000" and parts[0] != "lo":
                return parts[0]
    except OSError:
        pass
    return "eth0"


def get_ip(iface):
    try:
        import fcntl
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            return socket.inet_ntoa(
                fcntl.ioctl(s.fileno(), 0x8915,
                            struct.pack("256s", iface.encode()[:15]))[20:24])
        finally:
            s.close()
    except Exception:
        return ""


def get_mac(iface=None):
    base = Path("/sys/class/net")
    if iface:
        try:
            a = (base / iface / "address").read_text().strip()
            if a and a != "00:00:00:00:00:00":
                return a.upper()
        except OSError:
            pass
    try:
        for d in base.iterdir():
            a = (d / "address").read_text().strip()
            if a and a != "00:00:00:00:00:00":
                return a.upper()
    except OSError:
        pass
    return "00:00:00:00:00:00"


# --------------------------------------------------------------------------
# HTTP
# --------------------------------------------------------------------------
def http_get(url, headers=None, follow=False, timeout=10):
    u = urllib.parse.urlsplit(url)
    conn = http.client.HTTPConnection(u.hostname, u.port or 80, timeout=timeout)
    try:
        conn.request("GET", (u.path or "/") + ("?" + u.query if u.query else ""),
                     headers=headers or {})
        r = conn.getresponse()
        body = r.read()
        hdrs = {k.lower(): v for k, v in r.getheaders()}
        if follow and r.status in (301, 302, 303):
            loc = hdrs.get("location")
            if loc:
                return http_get(urllib.parse.urljoin(url, loc), headers, True, timeout)
        return r.status, hdrs, body
    finally:
        conn.close()


def http_post(url, body, headers, timeout=10):
    u = urllib.parse.urlsplit(url)
    conn = http.client.HTTPConnection(u.hostname, u.port or 80, timeout=timeout)
    try:
        conn.request("POST", (u.path or "/") + ("?" + u.query if u.query else ""),
                     body=body, headers=headers)
        r = conn.getresponse()
        b = r.read()
        hdrs = {k.lower(): v for k, v in r.getheaders()}
        return r.status, hdrs, b
    finally:
        conn.close()


def extract(src, start, end):
    i = src.find(start)
    if i < 0:
        return None
    i += len(start)
    j = src.find(end, i)
    return src[i:j] if j >= 0 else None


# --------------------------------------------------------------------------
# 会话算法模块（服务端下发的 .so）
# --------------------------------------------------------------------------
class SessionSo:
    """解析服务端下发的算法文件并调用 Code/DeCode。

    响应体格式(实测):
      001@<64位大写hex>$<GUID>]  +  [props 5B: ']' + 4B dict][uncomp_len 4B][LZMA流]
      LZMA流整体做过累加XOR混淆(stream[i-1] ^= stream[i] 从后往前)
    """

    def __init__(self, body: bytes):
        self.body = body
        self.guid = None
        self._lib = None

    def parse(self):
        """响应体: 状态码 + 长度字节分隔的字符串 + LZMA流
        001<len1><s1><len2><GUID>] <props4B(dict)> <uncomp_len4B> <LZMA流>
        ('@'=0x40=64 / '$'=0x24=36 在早期响应里恰为长度字节, 会变)"""
        b = self.body
        m = re.match(rb"^[0-9]+", b)
        if not m:
            raise RuntimeError(f"算法响应格式不识别: {b[:60]!r}")
        pos = m.end()
        if pos + 1 >= len(b):
            raise RuntimeError("算法响应过短")
        len1 = b[pos]; pos += 1
        s1 = b[pos:pos + len1]; pos += len1          # 引导 ticket(64/128位hex)
        if pos >= len(b):
            raise RuntimeError("算法响应缺少 GUID 段")
        len2 = b[pos]; pos += 1
        s2 = b[pos:pos + len2]; pos += len2          # 会话 GUID
        if re.fullmatch(rb"[0-9A-Fa-f]{32}", s2):
            g = s2.decode("ascii")
            self.guid = "%s-%s-%s-%s-%s" % (g[0:8], g[8:12], g[12:16], g[16:20], g[20:32])
        elif re.fullmatch(rb"[0-9A-Fa-f]{8}(-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}", s2):
            self.guid = s2.decode("ascii")
        else:
            raise RuntimeError(f"GUID 段不识别: {s2[:48]!r}")
        if pos + 12 >= len(b):
            raise RuntimeError("算法响应缺少数据段")
        props = None
        if b[pos] == 0x5D:                            # ']' 兼作 props[0] (lc3/lp0/pb2)
            props = bytes([0x5D]) + b[pos + 1:pos + 5]
            pos += 5
        else:
            props = b[pos:pos + 5]
            pos += 5
        (uncomp_len,) = struct.unpack("<I", b[pos:pos + 4])
        pos += 4
        stream = bytearray(b[pos:])
        for i in range(len(stream) - 1, 0, -1):
            stream[i - 1] ^= stream[i]
        lc = props[0] % 9
        rem = props[0] // 9
        lp = rem % 5
        pb = rem // 5
        dict_size = struct.unpack("<I", props[1:5])[0]
        log.info("LZMA props: lc=%d lp=%d pb=%d dict=%d", lc, lp, pb, dict_size)
        d = lzma.LZMADecompressor(
            format=lzma.FORMAT_RAW,
            filters=[{"id": lzma.FILTER_LZMA1, "dict_size": dict_size,
                      "lc": lc, "lp": lp, "pb": pb}],
        )
        so = d.decompress(bytes(stream))
        if len(so) != uncomp_len:
            log.warning("算法模块长度 %d != 期望 %d", len(so), uncomp_len)
        if so[:4] != b"ELF":
            raise RuntimeError("解压出的算法模块不是 ELF")
        so_path = Path(STATE_DIR) / "protect.so"
        so_path.parent.mkdir(parents=True, exist_ok=True)
        so_path.write_bytes(so)
        os.chmod(so_path, 0o700)
        self._lib = ctypes.CDLL(str(so_path))
        self._lib.Code.restype = ctypes.c_void_p
        self._lib.Code.argtypes = [ctypes.c_char_p]
        self._lib.DeCode.restype = ctypes.c_void_p
        self._lib.DeCode.argtypes = [ctypes.c_char_p]
        self._lib.FreeResult.restype = None
        self._lib.FreeResult.argtypes = [ctypes.c_void_p]
        log.info("会话算法已加载 (Algo-ID=%s, so=%d 字节)", self.guid, len(so))
        return self

    def encode(self, xml: str) -> str:
        p = self._lib.Code(xml.encode("utf-8"))
        if not p:
            raise RuntimeError("算法 Code() 返回空")
        try:
            return ctypes.string_at(p).decode("ascii")
        finally:
            self._lib.FreeResult(p)

    def decode(self, s: str) -> bytes:
        p = self._lib.DeCode(s.encode("ascii"))
        if not p:
            return b""
        try:
            return ctypes.string_at(p)
        finally:
            self._lib.FreeResult(p)


# --------------------------------------------------------------------------
# 拨号会话
# --------------------------------------------------------------------------
class Dialer:
    def __init__(self, cfg):
        self.cfg = cfg
        self.client_id = get_client_id()
        self.hostname = cfg.get("hostname") or socket.gethostname()[:15]
        self.iface = cfg.get("iface") or get_default_iface()
        self.client_ip = get_ip(self.iface) or "0.0.0.0"
        self.mac = (cfg.get("clientmac") or "").strip().upper() or get_mac(self.iface)
        self.schoolid = cfg.get("schoolid") or ""
        self.domain = cfg.get("domain") or ""
        self.area = cfg.get("area") or ""
        self.keep_retry = 6
        self.so = None
        self.ticket_url = None
        self.auth_url = None
        self.keep_url = None
        self.term_url = None
        self.ticket = None

    # ---- 发现 ----
    def discover(self):
        try:
            self._discover_chain()
            return
        except Exception as e:  # noqa: BLE001
            log.warning("标准发现失败(%s)，改用配置固定参数", e)
        if not (self.cfg.get("ticket_base") and self.cfg.get("auth_url")):
            raise RuntimeError("发现失败且未配置 ticket_base/auth_url")
        self.ticket_url = self._build_ticket(self.cfg["ticket_base"])
        self.auth_url = self.cfg["auth_url"]
        log.info("配置直连: ticket-url=%s", self.ticket_url)
        log.info("配置直连: auth-url=%s", self.auth_url)

    def _discover_chain(self):
        host = self.cfg.get("discover_host") or DISCOVER_HOST
        st, hdrs, _ = http_get(host, {"User-Agent": UA}, timeout=8)
        loc1 = hdrs.get("location")
        if not loc1:
            raise RuntimeError(f"{host} 未返回 302 (st={st})")
        st, hdrs, _ = http_get(loc1, {"User-Agent": UA}, timeout=8)
        self.schoolid = hdrs.get("schoolid") or self.schoolid
        self.domain = hdrs.get("domain") or self.domain
        self.area = hdrs.get("area") or self.area
        loc2 = hdrs.get("location")
        if not loc2:
            raise RuntimeError("第二跳无 Location")
        st, hdrs, body = http_get(loc2, {"User-Agent": UA}, timeout=8)
        text = body.decode("gb18030", "replace")
        t = extract(text, "<ticket-url><![CDATA[", "]]></ticket-url>")
        a = extract(text, "<auth-url><![CDATA[", "]]></auth-url>")
        if not (t and a):
            raise RuntimeError("配置页没有 ticket-url/auth-url")
        self.ticket_url = self._build_ticket(t)
        self.auth_url = a
        log.info("发现完成: schoolid=%s domain=%s area=%s", self.schoolid, self.domain, self.area)
        log.info("ticket-url=%s", self.ticket_url)
        log.info("auth-url=%s", self.auth_url)

    def _build_ticket(self, base):
        """base 无查询参数时, 用配置模板 + 当前 IP/MAC 补全"""
        base = base.rstrip("?")
        if urllib.parse.urlsplit(base).query:
            return base
        q = (self.cfg.get("ticket_params") or "").strip()
        if q:
            q = q.replace("{ip}", self.client_ip).replace("{mac}", self.mac)
        else:
            q = ("wlanacip=%s&wlanuserip=%s&clientip=%s&wlanacname=%s&clientmac=%s"
                 "&paip=%s&vlan=%s&iarmdst=%s&portal_node=%s") % (
                self.cfg.get("wlanacip"), self.client_ip, self.client_ip,
                self.cfg.get("wlanacname"), self.mac,
                self.cfg.get("paip"), self.cfg.get("vlan"),
                self.cfg.get("iarmdst"), self.cfg.get("portal_node"))
        return base + "?" + q

    # ---- 引导: 拿会话算法 ----
    def bootstrap(self):
        hdrs = {
            "User-Agent": UA,
            "Algo-ID": "00000000-0000-0000-0000-000000000000",
            "Client-ID": self.client_id,
            "CDC-Checksum": "0" * 32,
            "Connection": "close",
        }
        st, hdrs, body = http_post(self.ticket_url, "X", hdrs)
        log.info("引导请求: st=%d Error-Code=%s len=%d", st, hdrs.get("error-code"), len(body))
        self.so = SessionSo(body).parse()

    # ---- 请求 ----
    def post(self, url, xml):
        enc = self.so.encode(xml)
        hdrs = {
            "User-Agent": UA,
            "Algo-ID": self.so.guid,
            "Client-ID": self.client_id,
            "CDC-Checksum": hashlib.md5(enc.encode("ascii")).hexdigest(),
            "Connection": "close",
        }
        if self.schoolid:
            hdrs["CDC-SchoolId"] = self.schoolid
        if self.domain:
            hdrs["CDC-Domain"] = self.domain
        if self.area:
            hdrs["CDC-Area"] = self.area
        st, rh, body = http_post(url, enc, hdrs)
        code = rh.get("error-code")
        if code not in ("0", None):
            raise RuntimeError(f"{url} 返回 Error-Code {code}")
        dec = self.so.decode(body.decode("ascii", "replace")) if body else b""
        log.debug("响应(%s): %s", code, dec[:200])
        return dec

    def xml_ticket(self):
        return ('<?xml version="1.0" encoding="UTF-8"?><request>'
                f"<host-name>{self.hostname}</host-name><user-agent>{UA}</user-agent>"
                f"<client-id>{self.client_id}</client-id><ipv4>{self.client_ip}</ipv4>"
                "<ipv6></ipv6>"
                f"<mac>{self.mac}</mac><ostag>{OSTAG}</ostag>"
                f"<local-time>{now_str()}</local-time></request>")

    def xml_auth(self):
        return ('<?xml version="1.0" encoding="UTF-8"?><request>'
                f"<host-name>{self.hostname}</host-name><user-agent>{UA}</user-agent>"
                f"<userid>{self.cfg['user']}</userid><passwd>{self.cfg['pass']}</passwd>"
                f"<ticket>{self.ticket}</ticket><client-id>{self.client_id}</client-id>"
                f"<local-time>{now_str()}</local-time></request>")

    def xml_keep(self):
        return ('<?xml version="1.0" encoding="UTF-8"?><request>'
                f"<user-agent>{UA}</user-agent><local-time>{now_str()}</local-time>"
                f"<ticket>{self.ticket}</ticket><host-name>{self.hostname}</host-name>"
                f"<client-id>{self.client_id}</client-id></request>")

    def xml_term(self, reason):
        return ('<?xml version="1.0" encoding="UTF-8"?><request>'
                f"<user-agent>{UA}</user-agent><ticket>{self.ticket}</ticket>"
                f"<local-time>{now_str()}</local-time><host-name>{self.hostname}</host-name>"
                f"<reason>{reason}</reason><client-id>{self.client_id}</client-id></request>")

    # ---- 拨号 ----
    def dial(self):
        # 若 ticket_url 里带 clientmac, 以它为准 (与 portal 登记一致)
        q = urllib.parse.parse_qs(urllib.parse.urlsplit(self.ticket_url).query)
        mac = (q.get("clientmac") or q.get("wlanusermac") or [None])[0]
        if mac:
            self.mac = mac.upper()

        dec = self.post(self.ticket_url, self.xml_ticket())
        m = re.search(rb"<ticket>([0-9a-fA-F]+)</ticket>", dec)
        if not m:
            raise RuntimeError(f"ticket 响应无 <ticket>: {dec[:200]!r}")
        self.ticket = m.group(1).decode()
        log.info("ticket=%s", self.ticket)

        dec = self.post(self.auth_url, self.xml_auth())
        keep = extract(dec.decode("utf-8", "replace"), "<keep-url><![CDATA[", "]]></keep-url>")
        term = extract(dec.decode("utf-8", "replace"), "<term-url><![CDATA[", "]]></term-url>")
        if not keep:
            raise RuntimeError(f"认证响应没有 keep-url: {dec[:300]!r}")
        self.keep_url = keep
        self.term_url = term
        m = re.search(rb"<keep-retry>([0-9]+)</keep-retry>", dec)
        if m:
            self.keep_retry = int(m.group(1))
        log.info("认证成功: keep-url=%s term-url=%s keep-retry=%d",
                 keep, term, self.keep_retry)
        return True

    def keep(self):
        dec = self.post(self.keep_url, self.xml_keep())
        m = re.search(rb"<interval>([0-9]+)</interval>", dec)
        return int(m.group(1)) if m else int(self.cfg.get("interval") or 60)

    def term(self, reason=1):
        if self.ticket and self.term_url:
            try:
                self.post(self.term_url, self.xml_term(reason))
                log.info("已下线 (reason=%d)", reason)
            except Exception as e:  # noqa: BLE001
                log.warning("下线请求失败: %s", e)
        self.ticket = None


def online_check():
    try:
        st, _, _ = http_get("http://www.baidu.com/", {"User-Agent": UA}, timeout=6)
        return st == 200
    except Exception:
        return False


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description="ESurfing 天翼校园 Linux 无头拨号客户端 v2")
    ap.add_argument("--config", default=DEFAULT_CONF)
    ap.add_argument("--once", action="store_true", help="只拨号一次（测试用）")
    ap.add_argument("--force", action="store_true", help="跳过在线检查，强制重新拨号")
    ap.add_argument("--debug", action="store_true")
    args = ap.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        stream=sys.stderr,
    )

    cfg = load_conf(args.config)
    if not cfg["user"] or not cfg["pass"]:
        log.error("请在 %s 里配置 user= / pass=", args.config)
        return 1

    d = Dialer(cfg)

    def shutdown(signum, frame):
        log.info("收到信号 %d，正在下线...", signum)
        try:
            d.term(1)
        finally:
            sys.exit(0)

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)

    while True:
        try:
            if not args.force and online_check() and d.so is None and d.ticket is None:
                # 首次启动且已在线: 会话可能是别的进程建的, 重新拨号接管保活
                log.info("已在线但本进程无会话状态，重新拨号接管")
            d.discover()
            d.bootstrap()
            d.dial()
            log.info("拨号成功，开始心跳保活")
            if args.once:
                return 0
            fail = 0
            while True:
                try:
                    interval = d.keep()
                    fail = 0
                    time.sleep(max(1, min(interval, 600)))
                except Exception as e:  # noqa: BLE001
                    fail += 1
                    log.warning("心跳失败(%d): %s", fail, e)
                    if fail >= max(3, d.keep_retry):
                        raise
                    time.sleep(5)
        except Exception as e:  # noqa: BLE001
            log.error("拨号/保活失败: %s，%d 秒后重试", e,
                      int(cfg.get("retry_delay") or 10))
            try:
                d.term(1)
            except Exception:  # noqa: BLE001
                pass
            if args.once:
                return 1
            time.sleep(int(cfg.get("retry_delay") or 10))


if __name__ == "__main__":
    sys.exit(main())
