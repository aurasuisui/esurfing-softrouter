#!/bin/bash
# apply-patch.sh — 关闭 ESurfingSvr(2.4-64) 的"共享检测"组件 + 停止其自调度空转
#
# 依据逆向分析，本脚本打两个补丁：
#
# 补丁1 (文件偏移 0x223F8, vaddr 0x4223F8):
#   CWiFiSharedValidate::IsValidEnvironment()
#   原始: 55 48 89 E5  (push rbp; mov rbp,rsp)
#   改为: 31 C0 C3 90  (xor eax,eax; ret; nop)  -> 恒返回 0 = 环境正常
#   作用: 不再执行 ps -C 共享软件进程检查、不再检查内核 ip_forward，
#         检测结果恒为"未共享"，心跳不会上报 <shared>1</shared>。
#
# 补丁2 (文件偏移 0x26B12, vaddr 0x426B12):
#   CPortalServer::checkWifi()
#   原始: 55 48 89 E5  (push rbp; mov rbp,rsp)
#   改为: C3 90 90 90  (ret; nop; nop; nop)  -> 函数直接返回
#   作用: 不再创建/重复调度 checkWifi 定时任务(任务9/10)，避免守护进程
#         在无界面环境下 100% 占满 CPU 空转。
#
# 其余认证/保活/算法更新逻辑完全不动。
#
# 用法: sudo ./apply-patch.sh [ESurfingSvr路径]
set -euo pipefail

BIN="${1:-/usr/local/ESurfing/bin/ESurfingSvr}"
if [ ! -f "$BIN" ]; then
  echo "找不到 $BIN" >&2
  echo "用法: sudo $0 /path/to/ESurfingSvr" >&2
  exit 1
fi

# 只依赖 python3（Debian 13 必带），不依赖 xxd
read_hex() { # $1=offset
  python3 -c "import sys;f=open(sys.argv[1],'rb');f.seek(int(sys.argv[2],16));print(f.read(int(sys.argv[3],16)).hex());f.close()" "$BIN" "$1" 4
}
write_hex() { # $1=offset $2=hexbytes
  python3 -c "import sys;f=open(sys.argv[1],'r+b');f.seek(int(sys.argv[2],16));f.write(bytes.fromhex(sys.argv[3]));f.close()" "$BIN" "$1" "$2"
}

OFF1=0x223F8; ORIG1="554889e5"; PATCH1="31c0c390"
OFF2=0x26B12; ORIG2="554889e5"; PATCH2="c3909090"

echo "当前文件: $BIN"
need_backup=0
for i in 1 2; do
  eval "off=\$OFF$i orig=\$ORIG$i patch=\$PATCH$i"
  cur=$(read_hex "$off")
  echo "补丁$i @ 0x$(printf %x $off): 当前=$cur"
  if [ "$cur" = "$patch" ]; then
    echo "  -> 已打过，跳过"
    continue
  fi
  if [ "$cur" != "$orig" ]; then
    echo "错误: 补丁$i 处字节与 2.4-64 官方版本不匹配（期望 $orig，实际 $cur），拒绝修改。" >&2
    exit 1
  fi
  need_backup=1
done

if [ "$need_backup" = "1" ] && [ ! -f "$BIN.orig" ]; then
  cp -a "$BIN" "$BIN.orig"
  echo "已备份原始文件 -> $BIN.orig"
fi

for i in 1 2; do
  eval "off=\$OFF$i orig=\$ORIG$i patch=\$PATCH$i"
  cur=$(read_hex "$off")
  if [ "$cur" = "$patch" ]; then
    continue
  fi
  write_hex "$off" "$patch"
  after=$(read_hex "$off")
  echo "补丁$i 写入后: $after"
  [ "$after" = "$patch" ] || { echo "补丁$i 写入失败" >&2; exit 1; }
done

echo "OK: 两个补丁均已生效。"
echo "  sha256: $(sha256sum "$BIN" | cut -d' ' -f1)"
echo "  恢复原始行为: sudo cp '$BIN.orig' '$BIN'"
