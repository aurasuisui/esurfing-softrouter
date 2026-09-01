#!/bin/bash
# apply-patch.sh — 关闭 ESurfingSvr(2.4-64) 的"共享检测"组件
#
# 原理（依据逆向分析）:
#   CWiFiSharedValidate::IsValidEnvironment() 是唯一的本地共享检测入口
#   （ps -C 查共享软件进程 + 检查内核 ip_forward）。它只被
#   CPortalServer::CheckWiFiShare() 调用，返回非 0 即判定"共享"，
#   随后客户端会停止拨号任务并在 <logout-delay> 秒后强制下线。
#
#   本脚本把该函数入口改为  xor eax,eax; ret （永远返回 0 = 环境正常），
#   其余认证/保活/算法更新逻辑完全不改动。
#
# 补丁点: 文件偏移 0x223F8 (vaddr 0x4223F8)
#   原始: 55 48 89 E5  (push rbp; mov rbp,rsp)
#   改为: 31 C0 C3 90  (xor eax,eax; ret; nop)
#
# 用法: sudo ./apply-patch.sh [ESurfingSvr路径]
set -euo pipefail

BIN="${1:-/usr/local/ESurfing/bin/ESurfingSvr}"
if [ ! -f "$BIN" ]; then
  echo "找不到 $BIN" >&2
  echo "用法: sudo $0 /path/to/ESurfingSvr" >&2
  exit 1
fi

OFF=0x223F8
ORIG="554889e5"
PATCH="31c0c390"

# 只依赖 python3（Debian 13 必带），不依赖 xxd
read_hex() {
  python3 -c "import sys;f=open(sys.argv[1],'rb');f.seek(int(sys.argv[2],16));print(f.read(int(sys.argv[3],16)).hex());f.close()" "$BIN" "$OFF" 4
}
write_hex() {
  python3 -c "import sys;f=open(sys.argv[1],'r+b');f.seek(int(sys.argv[2],16));f.write(bytes.fromhex(sys.argv[3]));f.close()" "$BIN" "$OFF" "$PATCH"
}

cur=$(read_hex)
echo "当前文件: $BIN"
echo "偏移 0x223F8 处 4 字节: $cur"

if [ "$cur" = "$PATCH" ]; then
  echo "已打过补丁，无需重复操作。"
  exit 0
fi

if [ "$cur" != "$ORIG" ]; then
  echo "错误: 该文件与 2.4-64 官方版本不匹配（期望 $ORIG，实际 $cur），拒绝修改。" >&2
  exit 1
fi

# 备份
if [ ! -f "$BIN.orig" ]; then
  cp -a "$BIN" "$BIN.orig"
  echo "已备份原始文件 -> $BIN.orig"
fi

write_hex

after=$(read_hex)
echo "补丁后: $after"
if [ "$after" = "$PATCH" ]; then
  echo "OK: 共享检测(进程检查 + IP转发检查)已禁用。"
  echo "     sha256: $(sha256sum "$BIN" | cut -d' ' -f1)"
  echo "     恢复原始行为: sudo cp '$BIN.orig' '$BIN'"
else
  echo "补丁写入失败" >&2
  exit 1
fi
