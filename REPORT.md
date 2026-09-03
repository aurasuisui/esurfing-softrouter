# 天翼校园网（ESurfing）Linux 无头认证客户端 技术报告

> 从官方客户端逆向、到校方 portal 协议实测、再到干净客户端实现与软路由部署的完整记录。
> 配套仓库：https://github.com/aurasuisui/esurfing-softrouter

---

## 0. 摘要

目标：让一台 Debian 13（无显示器、multi-user.target/init 3）主机在无人值守下完成
天翼校园网（广东 CDC portal，cdcportal/1.4.2）认证拨号，并作为 NAT 软路由带下游
路由器（红米 AC2100）及全家设备上网，同时规避官方客户端内置的"共享检测"逻辑。

结论（全部实测通过）：

- 官方 daemon（ESurfingSvr 2.4-64）经五个幂等二进制补丁后可在无 GUI 环境运行；
- 但更可靠的方案是对校方 portal 协议做完整干净实现（esurfing_lite.py，纯 Python3
  标准库 + 服务端动态下发的会话算法 .so），开机自启、自动拨号、5 分钟心跳保活、
  优雅下线，全部验证通过；
- NAT/DHCP 层由 nftables + dnsmasq 实现并持久化，重启自愈；
- 转发链路吞吐实测损耗约 3%（64.3 → 62.2 Mbps，清华镜像 12 秒均值）。

---

## 1. 背景与目标

校园网认证通常依赖校方定制的拨号客户端，存在三个问题：

1. 官方客户端是 GUI 程序（Qt），无头环境无法运行；
2. 官方 daemon 内置"共享检测"：检测本机进程表与 ip_forward，一旦认为存在共享
   行为，心跳上报并在 300 秒后强制下线；
3. 官方客户端依赖校方下发/内置的编解码模块，协议本身不公开。

本项目目标：在自有机房/宿舍内，把官方客户端替换为可自动化的无头方案，并做
正常的 NAT 组网。所有分析与实现仅服务于"使用自己合法账号"的场景。

---

## 2. 环境与拓扑

- 软路由主机：Debian GNU/Linux 13 (trixie) x86_64，内核 6.12，无显示器；
  双千兆网口 eno1（WAN，DHCP 取校园网地址）+ enp1s0（LAN，接下游路由器）。
- 下游路由器：红米 AC2100（路由模式，双重 NAT）。
- 校方 portal：CDC 协议，portal 版本 cdcportal/1.4.2/gd-portal-12/13/40；
  入口为认证前 HTTP 劫持，认证后 portal 主机不再响应。

拓扑：

    校园网网线 ──> [Debian 13] eno1 (认证拨号+保活)
                     │ enp1s0 192.168.9.1/24 (dnsmasq DHCP)
                     └──> 红米 AC2100 WAN (自动获取 192.168.9.x)
                              └──> WiFi/LAN ──> 手机/电脑/平板

---

## 3. 官方客户端逆向分析

### 3.1 目标与工具链

官方包 linux-client-2.4-64 内含 daemon 二进制 ESurfingSvr（x86-64 ELF，
未剥离，含完整 DWARF 调试信息与符号表）与 GUI 程序 client。

分析在 Windows 上进行（无 objdump/readelf），使用 Python 生态替代：

- pyelftools：解析 ELF 段表/符号表/DWARF；
- capstone：反汇编指定虚拟地址；
- 文本/虚拟地址映射：.text 段 vaddr 基址 0x404940（文件偏移 0x4940），
  代码区 file_offset = vaddr - 0x400000。

由于符号完整，直接恢复出类结构与源文件名，逆向工作大幅简化。

### 3.2 总体架构（符号恢复结果）

    CPortalServer      认证流程主控（拨号链状态机、CheckNetStatus）
    CPortalConn        单次 HTTP 会话
    CPortalParser      协议解析（ticket/auth/keep/term）
    CWiFiSharedValidate 共享检测组件（重点分析对象）
    CSystemControl     平台抽象（Adapter/CentOS 两个实现）
    CZsmHelper         编解码模块管理（zxmAlogic.zxm）
    CMsgEngine / CTableTimer / CSimpleThread  消息队列/定时器/线程
    CPipeService / CServer / CClientCommand  与 GUI 的 IPC（无 GUI 时是麻烦根源）

daemon 与 GUI 分离：GUI 通过管道/服务驱动 daemon，daemon 本身设计为可被
GUI 完整控制；无 GUI 环境下多处逻辑走死分支。

### 3.3 共享检测机制（核心）

唯一调用入口：CPortalServer::CheckWiFiShare()（0x427FE0），登录成功后
按服务端下发的 againstList 周期调用 CWiFiSharedValidate::IsValidEnvironment()
（0x4223F8），逻辑：

    1. 进程检查：对 againstList 每个条目执行
       ps -C <进程短名> | wc -l
       结果 > 阈值即判定本机运行了 WiFi 共享软件；
    2. NAT 检查：检测内核 ip_forward
       - CentOS 分支：sysctl -a | grep ip_forward
       - 通用分支：旧式 sysctl() 系统调用（MIB {3,5,8,4}），在 >=5.5 内核
         上该系统调用已不可用，返回值不可信。

任一命中 → 记录 displayname，心跳包上报 <shared>1</shared>，
并在 logout-delay（默认 300 秒）后强制下线，GUI 提示"检测到共享软件冲突/
检测到共享冲突"。NAT 软路由必然命中 ip_forward 检查。

### 3.4 无 GUI 环境的缺陷（实测暴露）

1. 消息队列空转：CMsgEngine::DealMessageThread::GetMessage 空队列分支
   不阻塞不睡眠，纯自旋，无 GUI 时整核 100% CPU；
2. 拨号链不启动：CPortalServer::Start 两条路径在无 GUI 状态下走死分支：
   - 首启 m_pPortalConn==NULL 分支直接 return；
   - 状态分支只向 GUI 发消息，不触发 CheckNetStatus；
   结果 daemon 活着但永远不拨号（gdb 附加确认 Work 线程空转 500ms 循环）。
3. 共享检测在无 GUI 下同样会执行（心跳里带共享信息）。

### 3.5 二进制补丁方案（apply-patch.sh，幂等）

| 补丁 | 文件偏移(虚拟地址) | 修改 | 目的 |
|---|---|---|---|
| P1 | 0x223F8 (0x4223F8) | 55 48 89 E5 -> 31 C0 C3 90 | IsValidEnvironment 恒返回"环境正常"，禁用共享检测 |
| P2 | 0x26B12 (0x426B12) | 55 48 89 E5 -> C3 90 90 90 | checkWifi 直接返回，不再自调度 |
| P3 | 0x36539 (0x436539) | 空队列分支改为 Unlock+sleep(1)+重查 | 修复无 GUI 下 100% CPU 自旋 |
| P4 | 0x24BDF (0x424BDF) | 75 5E -> EB 5E (jne->jmp) | 强制进入拨号链 |
| P5 | 0x249F5 (0x4249F5) | E9 E1 02 00 00 -> E9 45 02 00 00 | Start 首启分支跳到 CheckNetStatus，无 GUI 也能拨号 |

脚本用 Python3 实现十六进制读写（无 xxd 依赖），补丁前校验原始字节、
备份 ESurfingSvr.orig，重复执行安全。补丁后 sha256：
16712a7378cd24aed5ddb590cbd150c4bbc2b1e722df2949042bee778db1ff9a。

验证手段：gdb -p <pid> 附加运行中的 daemon，
call (void) CPortalServer::GetInst()->CheckNetStatus(0) 直接触发拨号链成功，
证明入口选择正确。

---

## 4. 校方 CDC portal 协议逆向（实测）

官方 daemon 补丁后在无 GUI 环境仍有不可控因素（且从不下载 zxm 算法模块），
于是对 portal 本身做协议实测，全部通过构造 HTTP 请求 + 解析响应完成。

### 4.1 总体流程

    发现(302链) -> 引导(取会话算法) -> ticket -> auth -> keep 循环 -> term

### 4.2 发现链

    1. GET http://192.168.132.251/  (认证前 HTTP 被网关劫持)
       -> 302 Location 跳到 125.88.59.131:10001
    2. GET 上一跳 Location
       -> 响应头携带 schoolid/domain/area，302 跳到
          http://14.146.227.141:7001/index.cgi
    3. GET index.cgi（必须带 User-Agent: CCTP/Linux64/1003，否则返回
       瑞数 JS 挑战页 "CDC PrePortal (NO CCTP UserAgent)"）
       -> 页面注释 <!--config... 内含 <ticket-url>/<auth-url>/<state-url> CDATA

关键发现：认证成功后 portal 发现主机不再响应（超时），因此发现链只在
未认证状态可用；客户端必须支持"配置固定参数直连"降级。

### 4.3 会话算法下发（引导阶段）

向 ticket.cgi 发送任意内容（Algo-ID 任意、CDC-Checksum 任意），返回：

    HTTP Error-Code: 200
    body = 001@<64位大写hex>$<36位GUID>] <props尾4B><解压后长度4B><LZMA流>

其中 '@'=0x40=64 与 '$'=0x24=36 恰好是长度字节；后续实测出现过
0x80=128 位 ticket，即第一个字段长度可变——解析器必须按
"状态码 + 长度字节 + 字符串" 的通用格式解析，不能写死 @ 和 $。

数据段解析步骤（全部实测验证）：

    1. props[0] = 分隔符 ']' = 0x5D，后 4 字节为 LZMA1 dict_size；
       lc = 0x5D % 9 = 3, lp = (0x5D//9) % 5 = 0, pb = (0x5D//9)//5 = 2，
       dict = 1<<24 (16MB)；
    2. 4 字节小端 = 解压后长度（本次会话 38854 字节）；
    3. 剩余字节为累加异或混淆的 LZMA1 流：从尾到头执行
       stream[i-1] ^= stream[i] 还原；
    4. python lzma.LZMADecompressor(format=RAW, filters={lc/lp/pb/dict_size})
       解压出完整 ELF（共享库，导出 Code/DeCode/Prepare/Correct/FreeResult）。

会话算法每次下发内容不同（38310~41670 字节不等），格式一致。

### 4.4 请求编解码

ctypes 加载下发的 .so：

    Code(xml_utf8)      -> 大写 hex 字符串（请求体）
    DeCode(hex_string)  -> 明文 XML（响应体）
    FreeResult(ptr)     -> 释放返回值

HTTP 头约定：

    User-Agent:   CCTP/Linux64/1003
    Algo-ID:      引导响应里的 36 位 GUID
    Client-ID:    本机固定 UUID（大写，36 位）
    CDC-Checksum: MD5(编码串).hexdigest() 小写
    CDC-SchoolId / CDC-Domain / CDC-Area: 发现链第二跳的响应头值

### 4.5 认证请求（字段顺序敏感）

ticket 请求 XML（实测可用字段序）：

    <request>
      <host-name>主机名</host-name><user-agent>CCTP/Linux64/1003</user-agent>
      <client-id>UUID</client-id><ipv4>本机IP</ipv4><ipv6></ipv6>
      <mac>本机MAC</mac><ostag>linux64</ostag>
      <local-time>%Y-%m-%d %H:%M:%S</local-time>
    </request>

响应 Error-Code: 0，解码出 <ticket>32位小写hex</ticket>。

auth 请求（账号密码 + ticket + client-id）：

    <request>
      <host-name>..</host-name><user-agent>..</user-agent>
      <userid>账号</userid><passwd>密码</passwd>
      <ticket>上一步的ticket</ticket><client-id>UUID</client-id>
      <local-time>..</local-time>
    </request>

响应 Error-Code: 0 即认证成功，内含：

    keep-url   (http://14.146.227.142:7001/keep.cgi)
    term-url   (http://14.146.227.141:7001/term.cgi)
    keep-retry (6)

### 4.6 保活与下线

keep 请求（心跳）：

    <request><user-agent>..</user-agent><local-time>..</local-time>
      <ticket>认证ticket</ticket><host-name>..</host-name>
      <client-id>UUID</client-id></request>

响应 <interval>300</interval>——服务端要求每 300 秒心跳；连续失败达到
keep-retry(6) 次需重新走完整拨号链。

term 请求（下线）：字段与 keep 类似，附加 <reason>1</reason>；
响应 Error-Code: 0、body 为空。SIGTERM 时发送，保证服务端会话干净释放。

### 4.7 踩坑记录

| 现象 | 原因 | 解决 |
|---|---|---|
| auth 返回 Error-Code 14 | 复用了引导响应里的 bootstrap ticket | 必须先用会话算法发 ticket 请求换新 ticket |
| Error-Code 12 | 缺少 client-id 字段 | 补上固定 UUID |
| 引导响应解析失败 | 写死 '@'/'$' 分隔符，遇到 0x80 长度字节 | 改为通用长度字节解析 |
| 认证后 curl 不通 | 目标 IP 被校园网选择性拦截(个别公网 IP) | 用域名/换测试源，勿用单 IP 判断 |
| 发现链超时 | 认证成功后 portal 不再劫持 HTTP | 客户端降级为配置直连 |
| ticket URL 里 clientmac 与网卡不符 | 网关侧登记的是旧的 ARP 记录 | 以发现链返回为准；实测本机 MAC 也通过 |
| 无 CCTP UA 时 index.cgi 返回 JS 挑战页 | portal 有 UA 校验 | 固定 UA 头 |

---

## 5. 干净客户端实现（esurfing_lite.py v2）

设计原则：

- 仅 Python3 标准库 + 服务端下发的会话 .so（自动提取到
  /var/lib/esurfing-lite/protect.so，每次会话覆盖）；
- 不实现任何共享检测逻辑，心跳不带共享信息；
- 状态机：发现(降级) -> 引导 -> ticket -> auth -> keep 循环 -> term；
- 信号处理：SIGTERM/SIGINT 先发 term.cgi 再退出；
- 状态目录：/var/lib/esurfing-lite/（client-id、protect.so）；
- 关键参数全部配置化：/etc/esurfing/lite.conf（含 {ip}/{mac} 占位符的
  ticket_params 模板，换学校只需改配置）。

降级策略：发现链任一环节失败（超时/无 302/无配置页）即用 ticket_base +
ticket_params 构造 ticket URL 直连；auth_url 直接用配置值。该路径在
"已在线重拨"场景必经（发现主机在线后必超时）。

daemon 语义：每次启动总是完整拨号（即使检测到已在线）——旧会话可能是
别的进程建立且无人保活，重新拨号即可接管（实测重复认证会顶掉旧会话）。

---

## 6. 软路由部署

### 6.1 NAT（nftables，/etc/nftables.conf）

    table inet esurfing {
      chain postrouting { type nat hook postrouting priority srcnat; policy accept;
        oifname "eno1" masquerade }
      chain forward { type filter hook forward priority filter; policy accept;
        ct state established,related accept
        iifname "enp1s0" accept }
    }

配套 /etc/sysctl.d/40-ip-forward.conf 开启 ip_forward；nftables.service
开机加载规则。注意与 Docker 共存时 Docker 的 iptables-nft 表互不冲突
（本机实测 Docker FORWARD policy 为 ACCEPT，未产生干扰）。

### 6.2 DHCP（dnsmasq）

    interface=enp1s0
    bind-interfaces
    dhcp-range=192.168.9.100,192.168.9.200,12h
    dhcp-option=option:router,192.168.9.1
    dhcp-option=option:dns-server,192.168.9.1
    dhcp-authoritative

坑：dhcp-option 里 DNS 选项名是 option:dns-server（写成 option:dns 会
"bad dhcp-option"导致服务启动失败）。

### 6.3 LAN 静态地址（NetworkManager 自适应）

Debian 13 由 NetworkManager 管理网口。setup-nat.sh 检测到 NM 时用
nmcli 建/改 esurfing-lan 连接（禁掉同网口旧的自动连接），否则回退
ifupdown 写 /etc/network/interfaces.d/。

### 6.4 systemd 集成

    esurfing-lite.service: After=network-online.target, Restart=always,
    ExecStart=/usr/bin/python3 /opt/esurfing/esurfing-softrouter/lite/esurfing_lite.py
    dnsmasq.service + nftables.service: 系统原生服务，enable 即可

三服务全部 enable，重启后自动恢复：实测重启后 5 秒内完成拨号认证。

---

## 7. 实测数据

1. 完整拨号链（重启后自动完成，journalctl 实录）：

       发现完成: schoolid=1099 domain=sise.cn area=020
       引导请求: st=200 Error-Code=200 len=17044
       LZMA props: lc=3 lp=0 pb=2 dict=16777216
       会话算法已加载 (Algo-ID=..., so=38854 字节)
       ticket=1af7eaa8...
       认证成功: keep-url=... keep-retry=6
       拨号成功，开始心跳保活
       (心跳) 响应(0): <interval>300</interval>

2. SIGTERM 优雅下线：term.cgi 返回 Error-Code: 0，进程干净退出。
3. 吞吐（清华镜像 12 秒均值）：
   - Debian 直连 8.04 MB/s（64.3 Mbps）
   - netns 模拟下游经 NAT 7.77 MB/s（62.2 Mbps）
   - 转发损耗约 3%，证明瓶颈不在软路由；
4. 下游设备（红米 AC2100 WAN）自动获取 192.168.9.170，链路千兆全双工；
5. "手机测速只有 5Mbps"的定位过程：排除网线(千兆协商正常)、排除 NAT
   （netns 测速对照），最终确认是测速设备侧代理 TUN 网卡（198.18.0.1）
   与 2.4GHz 连接导致，与本方案无关。

---

## 8. 部署事故与教训（大事记）

| # | 事故 | 根因 | 处置 |
|---|---|---|---|
| 1 | 系统级 glibc 被旧库覆盖，sudo/cp/shutdown 全部报 GLIBC_2.2x not found | install.sh 把官方包 2016 年的 lib/ 全量拷入 /usr/local/ESurfing/lib 并注册进 ld.so.conf，旧 glibc 遮蔽系统库 | GRUB break=premount 进 initramfs，busybox 挂载根分区后清空 ld.so.conf.d 条目、删 ld.so.cache、删旧 lib，reboot；install.sh 重写为 ldd 依赖拷贝 + 基础库硬跳过清单 |
| 2 | cp ESurfingSvr 报"文本文件忙" | daemon 正在运行 | install.sh 先停服务+pkill+rm 再 cp |
| 3 | xxd 不存在 | 精简 Debian 未装 vim-common | 补丁脚本改用 Python3 十六进制读写 |
| 4 | 无 GUI daemon 100% CPU | GetMessage 空队列自旋 | 补丁 P3（sleep 1s） |
| 5 | daemon 活着但不拨号 | Start 死分支 | 补丁 P4/P5 + gdb 注入验证 |
| 6 | 写 /tmp/protect.so 报 ETXTBSY | 同名 .so 被前次会话占用 | 每次写唯一文件名 |
| 7 | dnsmasq 启动失败 | option:dns 不是合法名 | 改为 option:dns-server |
| 8 | SSH 突然"Connection closed" | 调试机网段切换 + 代理 TUN 劫持 | 改用 192.168.9.1 经 AC2100 链路管理 |

---

## 9. 风险与合规说明

- 本方案不做任何服务端欺骗：NAT 拓扑下服务端只能看到软路由一台设备、
  一个会话，"设备数量限制"针对的是并发认证会话数，本拓扑不触发；
- 官方客户端本地"共享检测"在本方案中不存在（干净实现）或被禁用（补丁）；
- 多设备共享账号可能违反学校网络使用条款，流量异常导致的封停风险由使用者
  自行承担；本项目仅用于合法账号下的自动化拨号与个人 NAT 组网；
- 会话算法 .so 由 portal 下发，客户端仅在本地提取使用，不外传。

## 10. 结论与后续

- 方案B（esurfing_lite）已在目标学校实测全流程通过，作为推荐方案；
  方案A（官方 daemon + 五补丁）保留作为备选与对照；
- 换学校/换城市时，按 lite/README-lite.md 的"参数获取方法"重新采集
  ticket_params/schoolid 等即可，协议框架通用；
- 若 portal 升级导致协议变化，用 esurfing_lite.py --debug 抓取交互细节，
  与本报告第 4 章对照即可定位差异。
