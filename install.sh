#!/bin/bash
# install.sh — 在 Debian 13 上安装"打过补丁"的 ESurfingSvr 并注册为系统服务
#
# 用法:
#   sudo ./install.sh <账号> <密码> [客户端包所在目录]
# 例:
#   sudo ./install.sh 20231234 'mypassword' /root/linux-client-2.4-64
#
# 会做什么:
#   1. 安装缺失的依赖库（libcrypto.so.10 / libssl.so.10 等旧库）
#   2. 复制 ESurfingSvr -> /usr/local/ESurfing/bin/
#   3. 打补丁禁用共享检测（apply-patch.sh）
#   4. 写入账号文件 /etc/esurfing/account (600)
#   5. 安装并启动 esurfing.service
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "请用 root 运行: sudo $0 <账号> <密码>" >&2
  exit 1
fi

ES_USER="${1:?用法: sudo $0 <账号> <密码> [客户端包目录]}"
ES_PASS="${2:?缺少密码参数}"
SRC_DIR="${3:-}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

if [ -z "$SRC_DIR" ]; then
  for cand in "$(dirname "$SCRIPT_DIR")" "$PWD"; do
    if [ -f "$cand/ESurfingSvr" ]; then SRC_DIR="$cand"; break; fi
  done
fi
if [ -z "${SRC_DIR:-}" ] || [ ! -f "$SRC_DIR/ESurfingSvr" ]; then
  echo "找不到 ESurfingSvr，请把第 3 个参数指向客户端包目录。" >&2
  exit 1
fi
echo "== 客户端包目录: $SRC_DIR =="

DEST=/usr/local/ESurfing
mkdir -p "$DEST/bin" "$DEST/lib" "$DEST/bin/conf"

# ---------- 1. 复制守护进程与配置 ----------
echo "== 安装 ESurfingSvr =="
# 防止"文本文件忙"：先停服务、结束残留进程、删除旧文件再覆盖
systemctl stop esurfing.service 2>/dev/null || true
pkill -f '/usr/local/ESurfing/bin/ESurfingSvr' 2>/dev/null || true
sleep 1
rm -f "$DEST/bin/ESurfingSvr"
cp -a "$SRC_DIR/ESurfingSvr" "$DEST/bin/ESurfingSvr"
chmod 755 "$DEST/bin/ESurfingSvr"
if [ -d "$SRC_DIR/conf" ]; then
  cp -a "$SRC_DIR"/conf/. "$DEST/bin/conf/"
fi
# 守护进程从自身目录读取 conf/conf.xml（redirect/detect.html 等）
echo "  已安装 -> $DEST/bin/ESurfingSvr"

# ---------- 2. 依赖库（只补真正缺失的，绝不覆盖系统基础库） ----------
echo "== 检查依赖库 =="
# 重要：官方包自带 2016 年的 glibc 等旧库，绝不能整包复制并加入 ld.so 搜索路径，
# 否则会"覆盖"系统 libc，导致 cp/sudo 等所有命令都无法执行。
# 这里只对已安装的 ESurfingSvr 跑 ldd，按缺失名单逐个补，并硬性跳过基础库。
MISSING="$(ldd "$DEST/bin/ESurfingSvr" 2>/dev/null | grep 'not found' | awk '{print $1}' || true)"
if [ -n "$MISSING" ] && [ -d "$SRC_DIR/lib" ]; then
  echo "  缺失库: $MISSING"
  for name in $MISSING; do
    case "$name" in
      libc.so.*|ld-linux*|libpthread*|libdl.so.*|libm.so.*|libselinux*|libz.so.*|libstdc++*|libgcc_s*)
        echo "  跳过基础库 $name（必须用系统版本）"; continue ;;
    esac
    if [ -f "$SRC_DIR/lib/$name" ]; then
      cp -a "$SRC_DIR/lib/$name" "$DEST/lib/"
      echo "  copied $name"
    else
      echo "  警告: 官方包内也没有 $name，请用 apt 安装"
    fi
  done
else
  echo "  所有依赖系统都有，无需复制旧库"
fi

# 安全兜底：万一基础库混了进来，立刻清掉整个 lib 目录
if ls "$DEST/lib" 2>/dev/null | grep -qE '^(libc\.so|ld-linux|libpthread|libdl\.so|libm\.so|libselinux|libz\.so|libstdc\+\+|libgcc_s)'; then
  echo "严重: 检测到基础库被复制，已自动清理。"
  rm -rf "$DEST/lib"
  mkdir -p "$DEST/lib"
fi

# 只有真的复制了库时才注册 ld 路径；否则把注册清理掉并重建缓存
if [ -n "$(ls -A "$DEST/lib" 2>/dev/null)" ]; then
  echo "$DEST/lib" > /etc/ld.so.conf.d/esurfing.conf
  ldconfig
else
  rm -f /etc/ld.so.conf.d/esurfing.conf
  ldconfig 2>/dev/null || true
  echo "  无需注册额外库路径"
fi

# ---------- 3. 打补丁：禁用共享检测 ----------
echo "== 打补丁禁用共享检测 =="
bash "$SCRIPT_DIR/apply-patch.sh" "$DEST/bin/ESurfingSvr"

# ---------- 4. 账号文件 ----------
echo "== 写入账号配置 =="
mkdir -p /etc/esurfing
umask 077
cat > /etc/esurfing/account <<EOF
ES_USER='$ES_USER'
ES_PASS='$ES_PASS'
EOF
echo "  -> /etc/esurfing/account (权限 600)"

# ---------- 5. systemd 服务 ----------
echo "== 安装 systemd 服务 =="
cp -a "$SCRIPT_DIR/esurfing.service" /etc/systemd/system/esurfing.service
systemctl daemon-reload
systemctl enable --now esurfing.service
sleep 2
systemctl --no-pager --full status esurfing.service || true

echo
echo "=============================================================="
echo "安装完成。常用命令:"
echo "  看日志:   journalctl -u esurfing -f"
echo "  重启拨号: systemctl restart esurfing"
echo "  停止:     systemctl stop esurfing"
echo "  验证补丁: bash $SCRIPT_DIR/apply-patch.sh $DEST/bin/ESurfingSvr"
echo "日志文件:   $DEST/bin/Log/Info.log"
echo "=============================================================="
