# 校园网软路由方案（Debian 13 / 天翼校园 ESurfing）

把 Debian 主机当作"校园网认证网关 + NAT 软路由"，下游接路由器，
手机/电脑/平板全部走这一条线。基于对官方客户端 linux-client-2.4-64
（ESurfingSvr）的反汇编分析 + 对校方 portal 的实测逆向实现。

## 拓扑

    校园网网线 ──> [Debian 13]
                     ├─ WAN 口: DHCP 拿校园网地址，本机跑认证拨号(保活)
                     ├─ NAT/masquerade
                     └─ LAN 口 ──> 路由器(WAN口) ──> 手机/电脑/平板
                                  (路由器开"路由模式"即可，自动获取IP)

## 目录结构

    esurfing-softrouter/
    ├── README.md                 本文件（部署指南）
    ├── REPORT.md                 技术报告：逆向分析/协议实测/问题与应对
    ├── install.sh                方案A安装脚本
    ├── apply-patch.sh            给官方守护进程打补丁（禁用共享检测）
    ├── esurfing.service          方案A 的 systemd 服务单元
    ├── router/
    │   ├── setup-nat.sh          NAT/软路由一键配置
    │   └── dnsmasq.conf.example  路由器开 AP 模式时的 DHCP/DNS（可选）
    └── lite/                     方案B：干净实现的客户端（推荐，已实测）
        ├── esurfing_lite.py      纯 Python3 标准库，无 GUI
        ├── esurfing-lite.service systemd 服务单元
        ├── lite.conf.example     配置示例（含参数获取方法）
        └── README-lite.md        详细文档

## 两个方案怎么选

| | 方案B：esurfing_lite（推荐） | 方案A：官方守护进程 + 补丁 |
|---|---|---|
| 认证/保活 | 完整重实现 CDC 协议，已在本校 portal 实测全流程（拨号/心跳/下线） | 原版 ESurfingSvr |
| 共享检测 | 本就没有 | 已禁用（五个补丁） |
| 无 GUI 稳定性 | 无 GUI 组件，开机自启实测通过 | 无 GUI 时存在自启动问题，需 P4/P5 补丁 |
| 部署 | 两条命令 | install.sh 一条命令 |

建议：**优先方案B**（干净、可控、已在真机验证）；方案A作为备选/对比参考。

## 快速开始（方案B，推荐）—— 手把手部署

### 第 0 步：确认硬件与接口（5 分钟）

校园网网线已插好、机器能通过 DHCP 拿到校园网地址的前提下，先弄清两个网口：

    ip -br link show
    ip -4 addr show | grep inet        # 找到校园网口(有 10.x/172.x/其他校园网段 IP 的)
    ip route show default              # 默认路由出口 = 校园网口(WAN)

假设结果：WAN 口 = eno1（校园网），LAN 口 = enp1s0（接路由器，此时无 IP 属正常）。
下文均按此举例，实际以你自己的网口名为准。

### 第 1 步：放置文件

    cd esurfing-softrouter
    sudo mkdir -p /opt/esurfing/esurfing-softrouter/lite /etc/esurfing
    sudo cp lite/esurfing_lite.py /opt/esurfing/esurfing-softrouter/lite/
    sudo cp lite/lite.conf.example /etc/esurfing/lite.conf

### 第 2 步：填配置（核心）

    sudo nano /etc/esurfing/lite.conf
    sudo chmod 600 /etc/esurfing/lite.conf

必填：user= / pass= 校园网账号密码。
学校参数（auth_url / ticket_base / ticket_params / schoolid / domain / area）获取方法
见 lite/lite.conf.example 文件内注释和 lite/README-lite.md 的"参数获取方法"一节。

### 第 3 步：安装并启动认证服务

    sudo cp lite/esurfing-lite.service /etc/systemd/system/
    sudo systemctl daemon-reload
    sudo systemctl enable --now esurfing-lite

30 秒内看到"认证成功"即为拨号成功：

    journalctl -u esurfing-lite -f
    # 预期依次出现:
    #   发现完成 / 标准发现失败(降级属正常) → 引导请求 → 会话算法已加载
    #   → ticket=... → 认证成功: keep-url=... → 拨号成功，开始心跳保活

验证本机已上网：

    curl -4 -o /dev/null -w '%{http_code}\n' http://www.baidu.com/   # 预期 200

### 第 4 步：配置软路由（NAT + DHCP 一键）

    sudo ./router/setup-nat.sh --wan eno1 --lan enp1s0 --lan-ip 192.168.9.1/24

脚本自动完成并**开机自恢复**：ip_forward、nftables MASQUERADE、
LAN 口静态地址(NetworkManager/ifupdown 自适应)、dnsmasq DHCP。
重跑幂等，可放心执行。预期输出末尾出现：

    NAT 配置完成。WAN 口: eno1 ... LAN 地址: 192.168.9.1/24 (已配 DHCP: 192.168.9.100-192.168.9.200)

### 第 5 步：接路由器

- **路由模式（推荐，最简单）**：网线从 debian 的 LAN 口接路由器 **WAN 口**，
  路由器保持出厂默认（WAN 自动获取 DHCP）。插上后路由器自动拿到 192.168.9.x 地址，
  确认方法：在 debian 上执行

        sudo cat /var/lib/misc/dnsmasq.leases     # 出现路由器主机名即成功

- AP/桥接模式：见 router/dnsmasq.conf.example（需要时再折腾）。

### 第 6 步：验收清单

    # ① 三个服务全部 active
    systemctl is-active esurfing-lite dnsmasq nftables

    # ② 模拟下游设备（可选，用 netns 验证 NAT 转发链路）
    sudo ip netns add t && sudo ip link add v0 type veth peer name v1
    sudo ip link set v1 netns t && sudo ip addr add 10.99.0.1/24 dev v0 && sudo ip link set v0 up
    sudo ip netns exec t sh -c 'ip addr add 10.99.0.2/24 dev v1; ip link set v1 up; ip route add default via 10.99.0.1; curl -4 -o /dev/null -w "%{http_code}\n" http://www.baidu.com/'
    sudo ip netns del t; sudo ip link del v0
    # 预期输出 200 = 转发链路正常

    # ③ 手机/电脑连路由器 WiFi 实测上网

### 第 7 步：重启验证（可选但强烈建议）

    sudo reboot

重启后无需任何人工干预，esurfing-lite 会自动重新拨号（实测 5 秒内完成认证），
NAT/DHCP 由 systemd 自恢复。这是"软路由无人值守"的最终验收。

## 常见问题排查（简表）

| 现象 | 排查 |
|---|---|
| 日志停在"引导请求"之后报错 | 学校 portal 协议变化，用 --debug 抓细节，对照 REPORT.md 协议章节 |
| 出现"标准发现失败，改用配置固定参数" | 正常降级（认证成功后 portal 发现地址必超时），能拨上号即可 |
| 手机网速异常低 | 先关代理软件再测；确认连的是 5GHz；有线链路问题见 REPORT.md 实测章节 |
| 重启后不能上网 | journalctl -u esurfing-lite 看拨号日志；ip route 看默认路由是否在校园网口 |
| 路由器 WAN 拿不到地址 | 确认 debian 侧插 LAN 口、路由器侧插 WAN 口；dnsmasq.leases 无记录则换网线 |

## 快速开始（方案A：官方守护进程 + 补丁）

> 也可以直接克隆整合仓库（官方包 + 本工具一次拿全）:
>
>     git clone --recurse-submodules https://github.com/aurasuisui/esurfing.git
>     cd esurfing/esurfing-softrouter
>
> 此时官方包就在 ../linux-client-2.4-64，可直接跳到第 1 步。

需要准备两样东西，都放到 Debian 机器上：

1. 官方客户端包 linux-client-2.4-64（学校发的那个文件夹，里面有
   ESurfingSvr、lib/、conf/。本仓库不含官方二进制，需要你提供这份原版包）；
2. 本仓库 esurfing-softrouter。

把它们放到同一个父目录（例如 /root/esurfing/），目录结构：

    /root/esurfing/
    ├── linux-client-2.4-64/     # 官方包
    └── esurfing-softrouter/     # 本仓库

    # 从 Windows 传官方包到 Debian:
    #   scp -r linux-client-2.4-64 root@<debian的IP>:/root/esurfing/
    # 在 Debian 上:
    #   cd /root/esurfing
    #   git clone https://github.com/aurasuisui/esurfing-softrouter.git
    #   cd esurfing-softrouter

    # 1. 安装并启动（第三个参数 = 官方包路径；与脚本同目录时可省略）
    sudo ./install.sh 你的账号 你的密码 ../linux-client-2.4-64

    # 2. 看拨号日志（账号无需 @ 后缀，报错码含义见 conf/code.xml）
    journalctl -u esurfing -f

    # 3. 之后同方案B第 3-5 步

## 方案A 的补丁做了什么（依据逆向分析）

官方 ESurfingSvr 里唯一的共享检测入口是
CWiFiSharedValidate::IsValidEnvironment()，它在登录后按服务器下发的
againstList 定期执行：

    1. ps -C <进程名> | wc -l   —— 查本机是否运行 WiFi 共享软件
    2. 读取内核 ip_forward（CentOS 分支: sysctl -a | grep ip_forward；
       通用分支: 旧 sysctl()）—— 查本机是否开了 NAT 转发

任一命中 → 记录 displayname，心跳上报 <shared>1</shared>，
并在 logout-delay(默认300秒) 后强制下线，GUI 报
"检测到共享软件冲突/检测到共享冲突"。

apply-patch.sh 一共打五个补丁（其余逻辑一字未动）：

1. IsValidEnvironment 入口（偏移 0x223F8）改为 "xor eax,eax; ret"，恒返回"环境正常"；
2. checkWifi（偏移 0x26B12）改为 "ret"，不再自调度定时任务；
3. CMsgEngine::GetMessage 的空队列分支（偏移 0x36539）改为 Unlock 后 sleep(1) 再查，
   修复无 GUI（无界面/服务器）运行时消息线程 100% 占满 CPU 的空转；
4. 拨号链启动条件（偏移 0x424BDF）jne 改 jmp，强制进入拨号流程；
5. CPortalServer::Start 首启分支（偏移 0x4249F5）改为跳转到 CheckNetStatus，
   修复无 GUI 下守护进程"只运行不拨号"的问题。

补丁幂等、会先备份 ESurfingSvr.orig 并校验原始字节，可随时恢复：

    sudo cp /usr/local/ESurfing/bin/ESurfingSvr.orig /usr/local/ESurfing/bin/ESurfingSvr

## 关于"绕过设备数量限制"的说明（请读完）

先说结论：在这个 NAT 拓扑下，**不需要对服务端做任何欺骗**，就能让全家设备共享：

1. **本地"共享检测"**：这是官方客户端自己的组件（进程检查 + ip_forward 检查）。
   方案B根本没实现，方案A把它补掉了。因此你开 NAT、开转发，客户端都不会
   再自我了断。
2. **服务端"终端数超出限制"(错误码 13014000)**：限制的是同一账号**同时在线的
   客户端会话数**。你的拓扑里只有 Debian 上的一个客户端在登录，所以正常
   情况下不会触发这个限制——限制检测不到你内网的设备。
3. 如果你的学校还在服务端做**流量指纹**（如 TTL、User-Agent、时间戳一致性）
   来识别 NAT：本客户端代码里没有任何这类机制（说明它是服务端行为，客户端
   无法主动"绕过"）。一种常用的加固手段是统一出口 TTL（setup-nat.sh 的
   --ttl 64 选项，把内网设备的 TTL 改成和 Linux 主机一致），这属于 NAT
   常规配置，但请自行判断是否符合校方管理规定。

风险提示：多人共享一个账号可能违反学校网络使用条款；账号因异常流量被校方
封停/拉黑的风险由使用者自行承担。

## 常见问题

* 方案B 日志出现"标准发现失败，改用配置固定参数"：正常降级行为，说明 portal
  发现链当前不可达（认证成功后必然如此），用配置里的固定参数直连即可。
* 方案B 参数怎么拿：见 lite/lite.conf.example 与 lite/README-lite.md。
* 方案A 首次拨号失败/算法相关报错：官方守护进程首次联网会从校方服务器下载
  zxmAlogic.zxm（编解码算法模块），确认 /usr/local/ESurfing/bin 可写、
  磁盘没满，等 1-2 分钟看日志重试。
* 需要 root：守护进程要写 /proc、改 DNS、在自身目录写日志/算法文件。
* 账号报"拨号类型错误/终端类型错误"：确认学校没关闭客户端通道，账号未欠费。
* 想验证补丁：sudo ./apply-patch.sh /usr/local/ESurfing/bin/ESurfingSvr
  （已打补丁时会提示"已打过补丁"）。
* systemd 里密码含特殊字符：install.sh 用单引号包裹写入，一般无需转义；
  若仍异常，手改 /etc/esurfing/account 后 systemctl restart esurfing。

## 免责声明

本工具仅用于：在你自己拥有合法上网账号、并拥有相关设备的前提下，把官方
客户端换成可自动化的无头拨号方案，以及在自有机房/宿舍内做正常的 NAT 组网。
请遵守所在学校的网络管理规定与当地法律法规。
