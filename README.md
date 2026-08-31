# 校园网软路由方案（Debian 13 / 天翼校园 ESurfing）

把 Debian 主机当作"校园网认证网关 + NAT 软路由"，下游接路由器，
手机/电脑/平板全部走这一条线。基于对官方客户端 linux-client-2.4-64
（ESurfingSvr）的反汇编分析实现。

## 拓扑

    校园网网线 ──> [Debian 13]
                     ├─ WAN 口: DHCP 拿校园网地址，本机跑认证拨号(保活)
                     ├─ NAT/masquerade
                     └─ LAN 口 ──> 路由器(WAN口) ──> 手机/电脑/平板
                                  (路由器开"路由模式"即可，自动获取IP)

## 目录结构

    esurfing-softrouter/
    ├── README.md                 本文件
    ├── install.sh                方案A安装脚本（推荐）
    ├── apply-patch.sh            给官方守护进程打补丁（禁用共享检测）
    ├── esurfing.service          systemd 服务单元
    ├── router/
    │   ├── setup-nat.sh          NAT/软路由一键配置
    │   └── dnsmasq.conf.example  路由器开 AP 模式时的 DHCP/DNS（可选）
    └── lite/                     方案B：干净实现的无头客户端（Beta）
        ├── esurfing_lite.py
        ├── esurfing-lite.service
        ├── lite.conf.example
        └── README-lite.md

## 两个方案怎么选

| | 方案A：官方守护进程 + 补丁（推荐） | 方案B：esurfing_lite（Beta） |
|---|---|---|
| 认证/保活/算法更新 | 原版 ESurfingSvr，学校怎么变都能跟上 | 自行重实现，只覆盖基本流程 |
| 共享检测 | 已禁用 | 本就没有 |
| 稳定性 | 高（就是官方拨号程序本身） | 需要按本校 portal 微调 |
| 部署 | install.sh 一条命令 | 手动两三条命令 |

建议：**先用方案A跑通**，之后想折腾再用方案B。

## 快速开始（方案A）

在 Debian 13（multi-user.target，即 init 3）上：

    # 1. 上传/拷贝客户端包(linux-client-2.4-64)与 esurfing-softrouter 到同一目录后:
    sudo ./install.sh 你的账号 你的密码 /路径/linux-client-2.4-64

    # 2. 看拨号日志（账号无需 @ 后缀，报错码含义见 conf/code.xml）
    journalctl -u esurfing -f

    # 3. 配置软路由（自动探测 WAN=默认路由口, LAN=另一个以太网口）
    sudo ./router/setup-nat.sh
    # 或显式指定：
    sudo ./router/setup-nat.sh --wan enp1s0 --lan enp2s0 --lan-ip 192.168.9.1/24

    # 4. 路由器接法
    #    路由模式: 路由器 WAN 口插 debian 的 LAN 口，路由器 WAN 设为 DHCP(自动获取)
    #    AP 模式:  关闭路由器 DHCP，插路由器 LAN 口，debian 上装 dnsmasq 提供 DHCP
    #              (见 router/dnsmasq.conf.example)

    # 5. 验证: 下游设备应能直接上网，出口 IP 是校园网分配给你的地址

## 补丁做了什么（依据逆向分析）

官方 ESurfingSvr 里唯一的共享检测入口是
CWiFiSharedValidate::IsValidEnvironment()，它在登录后按服务器下发的
againstList 定期执行：

    1. ps -C <进程名> | wc -l   —— 查本机是否运行 WiFi 共享软件
    2. 读取内核 ip_forward（CentOS 分支: sysctl -a | grep ip_forward；
       通用分支: 旧 sysctl()）—— 查本机是否开了 NAT 转发

任一命中 → 记录 displayname，心跳上报 <shared>1</shared>，
并在 logout-delay(默认300秒) 后强制下线，GUI 报
"检测到共享软件冲突/检测到共享冲突"。

apply-patch.sh 把该函数入口（文件偏移 0x223F8，vaddr 0x4223F8）从
"push rbp; mov rbp,rsp" 改为 "xor eax,eax; ret"（永远返回 0 = 环境正常），
其余逻辑一字未动。补丁幂等、会先备份 ESurfingSvr.orig 并校验原始字节，
可随时恢复：

    sudo cp /usr/local/ESurfing/bin/ESurfingSvr.orig /usr/local/ESurfing/bin/ESurfingSvr

## 关于"绕过设备数量限制"的说明（请读完）

先说结论：在这个 NAT 拓扑下，**不需要对服务端做任何欺骗**，就能让全家设备共享：

1. **本地"共享检测"**：这是官方客户端自己的组件（进程检查 + ip_forward 检查）。
   方案A把它补掉了，方案B根本没实现。因此你开 NAT、开转发，客户端都不会
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

* 首次拨号失败/算法相关报错：官方守护进程首次联网会从校方服务器下载
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
