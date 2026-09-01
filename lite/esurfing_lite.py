#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
esurfing_lite.py — 天翼校园(ESurfing/CDC portal) Linux 无头认证客户端（干净实现，Beta）

依据对 ESurfingSvr 2.4-64 的反汇编分析重新实现：
  * 协议: ticket.cgi -> auth.cgi -> keep.cgi(心跳) -> term.cgi(下线)
  * 请求体: XML，经"算法模块"(zxmAlogic.zxm 解压出的 protect.so)编码成十六进制串
  * 头:   User-Agent / Algo-ID / Client-ID / CDC-Checksum(=MD5(编码串)) / CDC-SchoolId / CDC-Domain / CDC-Area
  * 与官方客户端的区别: 不包含任何"共享检测"(ps -C 进程检查 / ip_forward 检查)，
    心跳请求里也永远不会携带 <shared>1</shared>。

依赖: 仅 Python 3 标准库（Debian 13 自带 python3）。
算法模块: 官方客户端首次联网时会从校方服务器下载 zxmAlogic.zxm，
          本程序直接复用该文件（解 LZMA 后 dlopen/ctypes 调用）。
          通常位于 /usr/local/ESurfing/bin/zxmAlogic.zxm 。

用法:
  python3 esurfing_lite.py --config /etc/esurfing/lite.conf [--once] [--daemon]
配置文件格式(KEY=VALUE):
  user=20231234
  pass=xxxx
  detect_url=http://14.146.227.141:7001/detect.html
  # 以下均可选
  ticket_url=http://.../ticket.cgi
  auth_url=http://.../auth.cgi
  keep_url=http://.../keep.cgi
  term_url=http://.../term.cgi
  client_ip=10.x.x.x
  cdc_schoolid=xxx
  cdc_domain=xxx
  cdc_area=xxx
  zxm_path=/usr/local/ESurfing/bin/zxmAlogic.zxm
  ua=CCTP/Linux64/1003
  ostag=linux64
"""

import argparse
import ctypes
import hashlib
import http.client
import lzma
import logging
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

UA_DEFAULT = "CCTP/Linux64/1003"
OSTAG_DEFAULT = "linux64"
DETECT_URL_DEFAULT = "http://14.146.227.141:7001/detect.html"


# --------------------------------------------------------------------------
# 配置
# --------------------------------------------------------------------------
def load_conf(path):
    cfg = {
        "user": None,
        "pass": None,
        "detect_url": DETECT_URL_DEFAULT,
        "ticket_url": None,
        "auth_url": None,
        "keep_url": None,
        "term_url": None,
        "client_ip": None,
        "mac": None,
        "cdc_schoolid": "",
        "cdc_domain": "",
        "cdc_area": "",
        "zxm_path": None,
        "ua": UA_DEFAULT,
        "ostag": OSTAG_DEFAULT,
        "hostname": None,
        "interval": 60,
        "retry_delay": 10,
    }
    p = Path(path)
    if p.exists():
        for line in p.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, _, v = line.partition("=")
            k = k.strip()
            v = v.strip().strip("'\"")
            if k in cfg:
                cfg[k] = v
    return cfg


def now_str():
    return time.strftime("%Y-%m-%d %H:%M:%S")


def get_mac(iface=None):
    """读取物理网卡 MAC；读不到就生成一个稳定的假 MAC。"""
    try:
        if iface:
            p = Path(f"/sys/class/net/{iface}/address")
            if p.exists():
                return p.read_text().strip().upper()
        for d in Path("/sys/class/net").iterdir():
            a = (d / "address").read_text().strip()
            if a and a != "00:00:00:00:00:00":
                return a.upper()
    except OSError:
        pass
    mac = uuid.uuid5(uuid.NAMESPACE_DNS, socket.gethostname() + "esurfing").bytes[:6]
    mac = bytes([mac[0] & 0xFE | 0x02]) + mac[1:]
    return ":".join(f"{b:02X}" for b in mac)


def get_client_id(path=None):
    if path is None:
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


def local_ip(portal=None):
    """尽量拿到校园网侧本机 IP（UDP connect 技巧）。"""
    if portal:
        try:
            host = urllib.parse.urlparse(portal).hostname
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect((host, 9))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except OSError:
            pass
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("223.5.5.5", 53))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except OSError:
        return "0.0.0.0"


# --------------------------------------------------------------------------
# 算法模块 (zxmAlogic.zxm -> protect.so -> ctypes)
# --------------------------------------------------------------------------
class ZsmCodec:
    """官方算法模块加载器/调用器。

    zxm 文件格式（逆向自 CZsmHelper::loadZsoModule）:
      [3 字节 magic][1字节长度+字符串][1字节长度+字符串(Algo-ID)]
      [5 字节 LZMA props(1 字节 lc/lp/pb + 4 字节 dict_size)]
      [4 字节 未压缩长度(LE)]
      [LZMA1 raw 流, 每个字节与其后一个字节做过累加 XOR]
    """

    def __init__(self, zxm_path):
        self.zxm = Path(zxm_path)
        self.magic = b""
        self.algo_id = "00000000-0000-0000-0000-000000000000"
        self._lib = None
        self._cb = None
        self._args = None

    # ---- zxm 解析 ----
    @staticmethod
    def _read_str_with_len(data, p):
        ln = data[p]
        return data[p + 1 : p + 1 + ln], p + 1 + ln

    def parse_container(self, data=None):
        """解析 zxm 容器，返回 (magic, algo_id, 解压后的 .so 内容)。"""
        data = data if data is not None else self.zxm.read_bytes()
        pos = 0
        # 3 字节 magic
        self.magic = data[pos : pos + 3]
        pos += 3
        # 两个长度前缀字符串
        self.name, pos = self._read_str_with_len(data, pos)
        self.algo_id, pos = self._read_str_with_len(data, pos)
        self.algo_id = self.algo_id.decode("ascii", "replace")

        # LZMA props（1 字节 lc/lp/pb + 4 字节 dict_size）
        props = data[pos : pos + 5]
        pos += 5
        prop = props[0]
        dict_size = struct.unpack("<I", props[1:5])[0]
        (uncomp_len,) = struct.unpack("<I", data[pos : pos + 4])
        pos += 4
        stream = bytearray(data[pos:])

        # 累加 XOR 解混淆: stream[i-1] ^= stream[i]（从后往前）
        for i in range(len(stream) - 1, 0, -1):
            stream[i - 1] ^= stream[i]

        lc = prop % 9
        rem = prop // 9
        lp = rem % 5
        pb = rem // 5
        try:
            so = lzma.decompress(
                bytes(stream),
                format=lzma.FORMAT_RAW,
                filters=[{
                    "id": lzma.FILTER_LZMA1,
                    "dict_size": dict_size,
                    "lc": lc,
                    "lp": lp,
                    "pb": pb,
                }],
            )
        except lzma.LZMAError as e:
            raise RuntimeError(f"LZMA 解压失败: {e}")
        if len(so) != uncomp_len:
            log.warning(
                "解压长度 %d != 期望 %d，仍尝试加载", len(so), uncomp_len
            )
        return so

    def load(self):
        so = self.parse_container()
        so_path = Path(STATE_DIR) / "protect.so"
        so_path.parent.mkdir(parents=True, exist_ok=True)
        so_path.write_bytes(so)
        os.chmod(so_path, 0o700)
        log.info("算法模块已解压: %s (Algo-ID=%s)", so_path, self.algo_id)

        # ---- dlopen ----
        self._lib = ctypes.CDLL(str(so_path))
        self._lib.Code.restype = ctypes.c_void_p
        self._lib.Code.argtypes = [ctypes.c_char_p]
        self._lib.FreeResult.restype = None
        self._lib.FreeResult.argtypes = [ctypes.c_void_p]
        self._lib.Prepare.restype = ctypes.c_int
        self._lib.Prepare.argtypes = [ctypes.c_void_p, ctypes.c_char_p,
                                      ctypes.c_void_p, ctypes.c_void_p]

        class Args(ctypes.Structure):
            _fields_ = [
                ("status", ctypes.c_int),
                ("size", ctypes.c_int),
                ("buf", ctypes.c_char_p),
            ]

        self._args = Args
        self._cb = ctypes.CFUNCTYPE(
            None, ctypes.c_void_p, ctypes.c_char_p, ctypes.c_void_p
        )(self._pp_cb)
        self._magic_p = ctypes.c_char_p(self.magic)
        return self

    @staticmethod
    def _pp_cb(ctx, data, args_p):
        """Prepare 的回调：负责把解码结果拷到调用方缓冲区（逆向自 ZsmPPCB）。"""
        need = len(data) + 1
        a = ctypes.cast(args_p, ctypes.POINTER(ZsmCodec._args)).contents
        if a.size < need:
            a.status = -1
            a.size = need
            return
        ctypes.memmove(a.buf, data, need)
        a.size = need

    def encode(self, xml: str) -> str:
        """明文 XML -> 编码串（十六进制）。"""
        if not self._lib:
            raise RuntimeError("算法模块未加载")
        p = self._lib.Code(xml.encode("utf-8"))
        if not p:
            raise RuntimeError("算法模块 Code() 返回空")
        try:
            return ctypes.string_at(p).decode("ascii")
        finally:
            self._lib.FreeResult(p)

    def decode(self, enc: str) -> str:
        """编码串 -> 明文 XML（官方实现还会把 GB18030 转成 UTF-8）。"""
        if not self._lib:
            raise RuntimeError("算法模块未加载")
        args = self._args(0, 0, None)
        enc_b = enc.encode("ascii")
        r = self._lib.Prepare(self._magic_p, enc_b, self._cb, ctypes.byref(args))
        if r != 1:
            raise RuntimeError(f"Prepare 第一次调用返回 {r}")
        buf = ctypes.create_string_buffer(max(args.size, 1))
        args2 = self._args(0, args.size, ctypes.cast(buf, ctypes.c_char_p))
        r = self._lib.Prepare(self._magic_p, enc_b, self._cb, ctypes.byref(args2))
        if r != 1:
            raise RuntimeError(f"Prepare 第二次调用返回 {r}")
        raw = buf.raw[: args2.size]
        for enc_name in ("utf-8", "gb18030", "latin1"):
            try:
                return raw.decode(enc_name)
            except (UnicodeDecodeError, ValueError):
                continue
        return raw.decode("latin1")


def find_zxm(cfg):
    cands = []
    if cfg.get("zxm_path"):
        cands.append(Path(cfg["zxm_path"]))
    cands += [
        Path("/usr/local/ESurfing/bin/zxmAlogic.zxm"),
        Path("/usr/local/ESurfing/lib/zxmAlogic.zxm"),
        Path.cwd() / "zxmAlogic.zxm",
        Path(__file__).resolve().parent / "zxmAlogic.zxm",
        Path(__file__).resolve().parent.parent / "zxmAlogic.zxm",
    ]
    for c in cands:
        if c.is_file():
            return c
    return None


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
        if follow and r.status in (301, 302, 303, 307):
            loc = r.getheader("Location")
            if loc:
                return http_get(urllib.parse.urljoin(url, loc), headers,
                                follow=True, timeout=timeout)
        return r.status, dict(r.getheaders()), body
    finally:
        conn.close()


def http_post(url, body, headers, timeout=10):
    u = urllib.parse.urlsplit(url)
    conn = http.client.HTTPConnection(u.hostname, u.port or 80, timeout=timeout)
    try:
        conn.request("POST", (u.path or "/") + ("?" + u.query if u.query else ""),
                     body=body, headers=headers)
        r = conn.getresponse()
        return r.status, r.read()
    finally:
        conn.close()


def extract(src, start, end):
    i = src.find(start)
    if i < 0:
        return None
    i += len(start)
    j = src.find(end, i)
    if j < 0:
        return None
    return src[i:j]


def extract_tag(src, tag):
    """优先 CDATA，其次普通标签。"""
    v = extract(src, f"<{tag}><![CDATA[", "]]></" + tag + ">")
    if v is not None:
        return v
    m = re.search(rf"<{tag}>(.*?)</{tag}>", src, re.S)
    return m.group(1) if m else None


# --------------------------------------------------------------------------
# 拨号流程
# --------------------------------------------------------------------------
class Dialer:
    def __init__(self, cfg):
        self.cfg = cfg
        self.codec = None
        self.client_id = get_client_id()
        self.hostname = cfg.get("hostname") or socket.gethostname()[:15]
        self.mac = cfg.get("mac") or get_mac()
        self.ua = cfg.get("ua") or UA_DEFAULT
        self.ostag = cfg.get("ostag") or OSTAG_DEFAULT
        self.ticket_url = cfg.get("ticket_url")
        self.auth_url = cfg.get("auth_url")
        self.keep_url = cfg.get("keep_url")
        self.term_url = cfg.get("term_url")
        self.client_ip = cfg.get("client_ip")
        self.ticket = None

    # ---- 发现 / 配置 ----
    def detect(self):
        """访问检测页，拿到重定向地址和 wlanuserip 等参数。"""
        url = self.cfg.get("detect_url") or DETECT_URL_DEFAULT
        log.info("检测网络状态: GET %s", url)
        status, headers, body = http_get(url, {"User-Agent": self.ua})
        loc = headers.get("Location") or headers.get("location")
        if not loc:
            m = re.search(rb'location\.href="([^"]+)"', body)
            if m:
                loc = m.group(1).decode("latin1")
        if loc:
            log.info("重定向: %s", loc)
            q = urllib.parse.parse_qs(urllib.parse.urlsplit(loc).query)
            if not self.client_ip:
                self.client_ip = (q.get("wlanuserip") or [None])[0]
            mac = (q.get("wlanusermac") or [None])[0]
            if mac and not self.cfg.get("mac"):
                self.mac = mac.upper()
            self.portal_url = loc
        else:
            self.portal_url = None
            log.info("没有重定向 —— 可能已在线，或 portal 检测方式不同")
        return self.portal_url

    def get_config(self):
        """从 portal 页面拿 ticket-url / auth-url。"""
        if self.ticket_url and self.auth_url:
            return
        if not self.portal_url:
            raise RuntimeError("没有 portal 地址，请手动配置 ticket_url/auth_url")
        log.info("获取配置: GET %s", self.portal_url)
        status, _, body = http_get(self.portal_url, {"User-Agent": self.ua})
        text = body.decode("gb18030", "replace")
        for tag, attr in (("ticket-url", "ticket_url"), ("auth-url", "auth_url"),
                          ("keep-url", "keep_url"), ("term-url", "term_url")):
            v = extract_tag(text, tag)
            if v and not getattr(self, attr):
                setattr(self, attr, v.strip())
        log.info("ticket-url=%s auth-url=%s keep-url=%s term-url=%s",
                 self.ticket_url, self.auth_url, self.keep_url, self.term_url)
        if not (self.ticket_url and self.auth_url):
            raise RuntimeError("portal 页面里没有 ticket-url/auth-url，"
                               "请抓包核对并在 lite.conf 里手动指定")

    # ---- 请求构造 ----
    def post(self, url, xml):
        if not self.codec:
            raise RuntimeError("算法模块未加载")
        body = self.codec.encode(xml)
        checksum = hashlib.md5(body.encode("ascii")).hexdigest().upper()
        headers = {
            "User-Agent": self.ua,
            "Algo-ID": self.codec.algo_id,
            "Client-ID": self.client_id,
            "CDC-Checksum": checksum,
            "Connection": "close",
        }
        if self.cfg.get("cdc_schoolid"):
            headers["CDC-SchoolId"] = self.cfg["cdc_schoolid"]
        if self.cfg.get("cdc_domain"):
            headers["CDC-Domain"] = self.cfg["cdc_domain"]
        if self.cfg.get("cdc_area"):
            headers["CDC-Area"] = self.cfg["cdc_area"]
        log.debug("POST %s  body=%s", url, body)
        status, resp = http_post(url, body, headers)
        log.debug("HTTP %d  resp=%s", status, resp[:300])
        if status != 200:
            raise RuntimeError(f"{url} 返回 HTTP {status}")
        return self.codec.decode(resp.decode("ascii", "replace"))

    def xml_ticket(self):
        return ('<?xml version="1.0" encoding="UTF-8"?><request>'
                f"<host-name>{self.hostname}</host-name>"
                f"<user-agent>{self.ua}</user-agent>"
                f"<client-id>{self.client_id}</client-id>"
                f"<ipv4>{self.client_ip or ''}</ipv4>"
                "<ipv6></ipv6>"
                f"<mac>{self.mac}</mac>"
                f"<ostag>{self.ostag}</ostag>"
                f"<local-time>{now_str()}</local-time>"
                "</request>")

    def xml_auth(self):
        return ('<?xml version="1.0" encoding="UTF-8"?><request>'
                f"<passwd>{self.cfg['pass']}</passwd>"
                f"<userid>{self.cfg['user']}</userid>"
                f"<ticket>{self.ticket}</ticket>"
                f"<client-id>{self.client_id}</client-id>"
                f"<host-name>{self.hostname}</host-name>"
                f"<user-agent>{self.ua}</user-agent>"
                f"<local-time>{now_str()}</local-time>"
                "</request>")

    def xml_keep(self):
        return ('<?xml version="1.0" encoding="UTF-8"?><request>'
                f"<user-agent>{self.ua}</user-agent>"
                f"<local-time>{now_str()}</local-time>"
                f"<ticket>{self.ticket}</ticket>"
                f"<host-name>{self.hostname}</host-name>"
                f"<client-id>{self.client_id}</client-id>"
                "</request>")

    def xml_term(self, reason):
        return ('<?xml version="1.0" encoding="UTF-8"?><request>'
                f"<user-agent>{self.ua}</user-agent>"
                f"<ticket>{self.ticket}</ticket>"
                f"<local-time>{now_str()}</local-time>"
                f"<host-name>{self.hostname}</host-name>"
                f"<reason>{reason}</reason>"
                f"<client-id>{self.client_id}</client-id>"
                "</request>")

    # ---- 拨号 ----
    def dial(self):
        if not self.client_ip:
            self.client_ip = local_ip(self.ticket_url or self.cfg.get("detect_url"))
        log.info("本机IP=%s MAC=%s ClientID=%s", self.client_ip, self.mac, self.client_id)

        resp = self.post(self.ticket_url, self.xml_ticket())
        self.ticket = extract_tag(resp, "ticket")
        if not self.ticket:
            raise RuntimeError(f"响应中没有 ticket: {resp[:200]}")
        log.info("ticket=%s", self.ticket)

        resp = self.post(self.auth_url, self.xml_auth())
        for tag, attr in (("keep-url", "keep_url"), ("term-url", "term_url")):
            v = extract_tag(resp, tag)
            if v:
                setattr(self, attr, v.strip())
        log.info("认证响应: %s", resp[:300])
        if not self.keep_url:
            raise RuntimeError("认证响应中没有 keep-url（认证可能失败）")
        return True

    def keep(self):
        resp = self.post(self.keep_url, self.xml_keep())
        iv = extract_tag(resp, "interval")
        interval = int(iv) if iv and iv.strip().isdigit() else None
        log.debug("keep 响应: %s", resp[:200])
        return interval or int(self.cfg.get("interval") or 60)

    def term(self, reason=1):
        if self.ticket and self.term_url:
            try:
                self.post(self.term_url, self.xml_term(reason))
                log.info("已下线 (reason=%d)", reason)
            except Exception as e:  # noqa: BLE001
                log.warning("下线请求失败: %s", e)
        self.ticket = None


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description="ESurfing 天翼校园 Linux 无头拨号客户端")
    ap.add_argument("--config", default=DEFAULT_CONF)
    ap.add_argument("--once", action="store_true", help="只拨号一次（测试用）")
    ap.add_argument("--force", action="store_true", help="跳过在线检测，直接拨号")
    ap.add_argument("--debug", action="store_true")
    ap.add_argument("--user", "--pass", dest="user", help="覆盖配置中的账号")
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
    try:
        zxm = find_zxm(cfg)
        if not zxm:
            log.error("找不到算法文件 zxmAlogic.zxm。")
            log.error("请先运行一次官方客户端（或本包 install.sh 安装的守护进程）")
            log.error("让它从校方服务器下载算法，然后再运行本程序；")
            log.error("也可以把 zxmAlogic.zxm 放到 /usr/local/ESurfing/bin/ 下。")
            return 1
        d.codec = ZsmCodec(zxm).load()
    except Exception as e:  # noqa: BLE001
        log.error("算法模块加载失败: %s", e)
        return 1

    def shutdown(signum, frame):
        log.info("收到信号 %d，正在下线...", signum)
        try:
            d.term(1)
        finally:
            sys.exit(0)

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)

    # 在线检测
    if not args.force and not (d.ticket_url and d.auth_url and d.client_ip):
        try:
            d.detect()
        except Exception as e:  # noqa: BLE001
            log.warning("检测失败: %s（继续尝试拨号）", e)

    try:
        d.get_config()
    except Exception as e:  # noqa: BLE001
        if not (d.ticket_url and d.auth_url):
            log.error("配置获取失败: %s", e)
            return 1

    while True:
        try:
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
                    if fail >= 3:
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
