#!/bin/bash
# apply-patch.sh — 让 ESurfingSvr(2.4-64) 适合无界面(服务器/软路由)运行
#
# 依据逆向分析，本脚本打三个补丁：
#
# 补丁1 (文件偏移 0x223F8, vaddr 0x4223F8):
#   CWiFiSharedValidate::IsValidEnvironment()
#   改为: 31 C0 C3 90  (xor eax,eax; ret; nop) -> 恒返回 0 = 环境正常
#   作用: 不再执行 ps -C 共享软件进程检查、不再检查内核 ip_forward，
#         检测结果恒为"未共享"，心跳不会上报 <shared>1</shared>。
#
# 补丁2 (文件偏移 0x26B12, vaddr 0x426B12):
#   CPortalServer::checkWifi()
#   改为: C3 90 90 90  (ret; nop; nop; nop) -> 函数直接返回
#   作用: 不再创建/重复调度 checkWifi 定时任务(任务9/10)。
#
# 补丁3 (文件偏移 0x36539, vaddr 0x436539, 29 字节):
#   CMsgEngine::GetMessage() 的"队列为空"分支
#   原逻辑: Unlock 后立刻回到 Lock 再查队列 -> 无 GUI 时 100% 占满 CPU 空转
#   改为:   Unlock 后 sleep(1) 再回到 Lock
#   作用: 消息线程空闲时每秒只醒一次，CPU 占用归零。
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
read_hex() { # $1=offset(十六进制) $2=字节数(十进制)
  python3 -c "import sys;f=open(sys.argv[1],'rb');f.seek(int(sys.argv[2],16));print(f.read(int(sys.argv[3])).hex());f.close()" "$BIN" "$1" "$2"
}
write_hex() { # $1=offset $2=hex串
  python3 -c "import sys;f=open(sys.argv[1],'r+b');f.seek(int(sys.argv[2],16));f.write(bytes.fromhex(sys.argv[3]));f.close()" "$BIN" "$1" "$2"
}

P1_OFF=0x223F8; P1_ORIG="554889e5"; P1_PATCH="31c0c390"
P2_OFF=0x26B12; P2_ORIG="554889e5"; P2_PATCH="c3909090"
P3_OFF=0x36539
P3_ORIG="488b45f84883c0584889c7e853f5ffff488b45f80fb6808800000084c0"
P3_PATCH="488d7df84883c758e856f5ffffbf01000000e8f0dcfcffe96cffffff90"

echo "当前文件: $BIN"
need_backup=0
for i in 1 2 3; do
  eval "off=\$P${i}_OFF orig=\$P${i}_ORIG patch=\$P${i}_PATCH"
  len=$((${#orig}/2))
  cur=$(read_hex "$off" "$len")
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

for i in 1 2 3; do
  eval "off=\$P${i}_OFF orig=\$P${i}_ORIG patch=\$P${i}_PATCH"
  len=$((${#orig}/2))
  cur=$(read_hex "$off" "$len")
  if [ "$cur" = "$patch" ]; then
    continue
  fi
  write_hex "$off" "$patch"
  after=$(read_hex "$off" "$len")
  echo "补丁$i 写入后: $after"
  [ "$after" = "$patch" ] || { echo "补丁$i 写入失败" >&2; exit 1; }
done

echo "OK: 三个补丁均已生效。"
echo "  sha256: $(sha256sum "$BIN" | cut -d' ' -f1)"
echo "  恢复原始行为: sudo cp '$BIN.orig' '$BIN'"
