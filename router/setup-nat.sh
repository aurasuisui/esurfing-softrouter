#!/bin/bash
# setup-nat.sh — 把 Debian 主机配置成校园网软路由（NAT 网关）
#
# 拓扑:
#   校园网网线 ── WAN口(debian, DHCP拿校园网地址) ── debian ── LAN口 ── 路由器 ── 手机/电脑/平板
#             [ESurfingSvr 在 debian 上拨号认证]       [NAT/masquerade]
#
# 用法:
#   sudo ./setup-nat.sh                          # 自动探测 WAN(默认路由)/LAN
#   sudo ./setup-nat.sh --wan enp1s0 --lan enp2s0
#   sudo ./setup-nat.sh --wan enp1s0 --lan enp2s0 --lan-ip 192.168.9.1/24
#       (推荐带 --lan-ip: 自动配置 LAN 静态地址 + dnsmasq DHCP, 下游路由器 WAN 直接自动获取)
#   sudo ./setup-nat.sh --ttl 64                 # 额外: 出口包 TTL 统一为 64(防 TTL 指纹, 可选)
set -euo pipefail

WAN=""
LAN=""
LAN_IP=""
TTL=""
while [ $# -gt 0 ]; do
  case "$1" in
    --wan) WAN="${2:?--wan 需要参数}"; shift 2;;
    --lan) LAN="${2:?--lan 需要参数}"; shift 2;;
    --lan-ip) LAN_IP="${2:?--lan-ip 需要参数}"; shift 2;;
    --ttl) TTL="${2:?--ttl 需要参数}"; shift 2;;
    *) echo "未知参数 $1"; exit 1;;
  esac
done

if [ -z "$WAN" ]; then
  WAN=$(ip route show default 2>/dev/null | awk '{print $5; exit}')
fi
if [ -z "$WAN" ]; then
  echo "检测不到默认路由（校园网口可能还没插线/没拿到地址），请用 --wan 指定。" >&2
  exit 1
fi

if [ -z "$LAN" ]; then
  # 找一个已存在的、非 WAN 的以太网口
  LAN=$(ip -o link show | awk -F': ' '{print $2}' | grep -E '^(en|eth)' | grep -vx "$WAN" | head -1)
fi
if [ -z "$LAN" ]; then
  echo "找不到 LAN 口，请用 --lan 指定（例如 enp2s0）。" >&2
  exit 1
fi

echo "WAN(校园网口): $WAN"
echo "LAN(接路由器口): $LAN"

mkdir -p /etc/esurfing
cat > /etc/esurfing/nat.env <<EOF
WAN=$WAN
LAN=$LAN
LAN_IP=$LAN_IP
TTL=$TTL
EOF
chmod 600 /etc/esurfing/nat.env

# ---------- 1. 开启转发 ----------
cat > /etc/sysctl.d/40-ip-forward.conf <<'EOF'
# 校园网软路由：开启 IPv4/IPv6 转发
net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
EOF
sysctl -p /etc/sysctl.d/40-ip-forward.conf >/dev/null

# ---------- 2. nftables ----------
if command -v nft >/dev/null; then
  if [ -n "$TTL" ]; then
    TTL_LINE="oifname \"$WAN\" ip ttl set $TTL"
  else
    TTL_LINE="# 可选: 若担心服务端做TTL指纹识别NAT, 取消下一行注释(值一般填64)"
  fi
  cat > /etc/nftables.conf <<EOF
#!/usr/sbin/nft -f
flush ruleset

table inet esurfing {
  chain postrouting {
    type nat hook postrouting priority srcnat; policy accept;
    oifname "$WAN" masquerade
    $TTL_LINE
  }
  chain forward {
    type filter hook forward priority filter; policy accept;
    ct state established,related accept
    iifname "$LAN" accept
  }
}
EOF
  chmod 640 /etc/nftables.conf
  systemctl enable nftables.service >/dev/null 2>&1 || true
  systemctl restart nftables.service
  echo "nftables 规则已写入 /etc/nftables.conf 并生效"
else
  echo "未找到 nft，请 apt install nftables 后重新运行本脚本。" >&2
fi

# ---------- 3. LAN 静态地址 + DHCP（可选, 带 --lan-ip 时启用） ----------
if [ -n "$LAN_IP" ]; then
  LAN_ADDR="${LAN_IP%/*}"
  NET="${LAN_ADDR%.*}"

  echo "配置 $LAN 静态地址 $LAN_IP"
  if command -v nmcli >/dev/null 2>&1 && systemctl is-active NetworkManager >/dev/null 2>&1; then
    # NetworkManager 管理(Debian 默认): 先禁掉该网口旧的自动连接, 再建/改 esurfing-lan
    while IFS=: read -r name _ _ dev; do
      if [ "$dev" = "$LAN" ] && [ "$name" != "esurfing-lan" ]; then
        echo "  禁用旧连接 $name"
        nmcli con down "$name" 2>/dev/null || true
        nmcli con mod "$name" connection.autoconnect no 2>/dev/null || true
      fi
    done < <(nmcli -t con show 2>/dev/null)
    if ! nmcli -t con show | grep -q '^esurfing-lan:'; then
      nmcli con add type ethernet con-name esurfing-lan ifname "$LAN" \
        ipv4.method manual ipv4.addresses "$LAN_IP" ipv6.method ignore
    else
      nmcli con mod esurfing-lan ipv4.method manual ipv4.addresses "$LAN_IP" ipv6.method ignore
    fi
    nmcli con mod esurfing-lan connection.autoconnect yes
    nmcli con up esurfing-lan || true
  else
    # ifupdown 路径
    mkdir -p /etc/network/interfaces.d
    cat > /etc/network/interfaces.d/esurfing-lan <<EOF
auto $LAN
iface $LAN inet static
    address $LAN_ADDR
    netmask 255.255.255.0
EOF
    if command -v ifup >/dev/null; then ifup "$LAN" || true; fi
  fi

  # dnsmasq: 给下游路由器 WAN 口发地址(实测通过: 红米 AC2100 直接拿到 192.168.9.x)
  if ! command -v dnsmasq >/dev/null 2>&1; then
    echo "安装 dnsmasq ..."
    apt-get install -y dnsmasq
  fi
  mkdir -p /etc/dnsmasq.d
  cat > /etc/dnsmasq.d/esurfing.conf <<EOF
# 校园网软路由: 给下游路由器 WAN 口发地址 (由 setup-nat.sh 生成)
interface=$LAN
bind-interfaces
dhcp-range=$NET.100,$NET.200,12h
dhcp-option=option:router,$LAN_ADDR
dhcp-option=option:dns-server,$LAN_ADDR
dhcp-authoritative
EOF
  systemctl enable dnsmasq.service >/dev/null 2>&1 || true
  systemctl restart dnsmasq.service
  echo "dnsmasq 已配置: $LAN DHCP $NET.100-$NET.200 网关/DNS=$LAN_ADDR"
fi

echo
echo "=============================================================="
echo "NAT 配置完成。"
echo "  WAN 口: $WAN (MASQUERADE 出口)"
echo "  LAN 口: $LAN (接路由器 WAN 口)"
if [ -n "$LAN_IP" ]; then
  echo "  LAN 地址: $LAN_IP (已配 DHCP: $NET.100-$NET.200)"
fi
echo "  转发开关: /etc/sysctl.d/40-ip-forward.conf"
echo "  防火墙:   /etc/nftables.conf"
echo "=============================================================="
echo
echo "下游路由器的接法（两种任选）:"
echo "  A. 路由器开『路由模式』: 路由器 WAN 口接 debian 的 $LAN 口，WAN 设为自动获取(DHCP)。"
echo "     最简单，所有设备在路由器后面，双重 NAT 对校园网无影响。"
echo "     (本脚本已配好 DHCP, 路由器重置后插上即可自动拿到地址)"
echo "  B. 路由器开『AP/桥接模式』: 关闭路由器 DHCP，网线插路由器 LAN 口；"
echo "     此时由 debian 提供 DHCP，见 router/dnsmasq.conf.example。"
