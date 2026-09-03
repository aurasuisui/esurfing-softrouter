# esurfing_lite — 天翼校园 Linux 无头认证客户端 (v2)

纯 Python3 标准库实现的干净客户端，已在本校 portal（cdcportal/1.4.2/gd-portal-12，广东 CDC 协议）上实测通过完整认证流程。

与官方 ESurfingSvr 不同：

- **不包含任何"共享检测"逻辑**：官方 daemon 会读服务端下发的 againstList 检查本机进程/IP 转发状态并上报，本实现完全不走这套流程；
- 心跳请求不带共享信息，NAT 软路由场景下对端只看到一台设备（软路由本身）；
- 无 GUI、无 Qt 依赖，仅用 Python 标准库 + 服务端动态下发的会话算法 .so（自动提取、自动加载）。

## 工作原理（实测协议）

    发现         GET 192.168.132.251 -> 302 -> (schoolid/domain/area 响应头)
                 -> 302 -> index.cgi 页面注释里的 <ticket-url>/<auth-url>
                 (发现链不通时自动降级为配置文件里的固定参数直连)

    引导         向 ticket.cgi 发任意内容 -> 响应体 = 会话算法文件
                 (001@<ticket>$<GUID>] + LZMA1 压缩的 .so, 带累加XOR混淆)

    会话算法     解压 .so, ctypes 加载; Code() 编码请求 / DeCode() 解码响应;
                 Algo-ID 头 = 响应里的 GUID, CDC-Checksum = MD5(编码串) 小写

    认证         ticket 请求 -> <ticket> -> auth 请求(账号/密码/ticket/client-id)
                 -> 返回 keep-url / term-url / keep-retry

    保活         每 <interval> 秒 POST keep.cgi 心跳

    下线         SIGTERM/SIGINT -> term.cgi -> 退出

## 安装（软路由 Debian 无头）

    # 1. 放到固定位置
    sudo mkdir -p /opt/esurfing/esurfing-softrouter/lite
    sudo cp esurfing_lite.py /opt/esurfing/esurfing-softrouter/lite/
    sudo chmod +x /opt/esurfing/esurfing-softrouter/lite/esurfing_lite.py

    # 2. 配置 (必改: user/pass; 其余学校参数见 lite.conf.example 注释)
    sudo mkdir -p /etc/esurfing
    sudo cp lite.conf.example /etc/esurfing/lite.conf
    sudo chmod 600 /etc/esurfing/lite.conf

    # 3. systemd 服务 (与官方 esurfing.service 二选一, 不要同时启用)
    sudo cp esurfing-lite.service /etc/systemd/system/
    sudo systemctl daemon-reload
    sudo systemctl disable --now esurfing.service   # 停用官方 daemon
    sudo systemctl enable --now esurfing-lite

    # 4. 查看状态
    journalctl -u esurfing-lite -f

## 手动运行

    sudo python3 esurfing_lite.py --once            # 拨号一次, 适合调试
    sudo python3 esurfing_lite.py --debug           # 前台运行, 打印全部协议细节
    sudo python3 esurfing_lite.py --force           # 跳过在线检查强制重新拨号

状态目录：/var/lib/esurfing-lite/（client-id、protect.so 缓存）。

## 参数获取方法（换学校/换城市时）

1. 认证前在软路由上执行：
   curl -A "CCTP/Linux64/1003" -D - -o /dev/null http://<detect_host>/
   跟着 302 跳 3 次，记录第二跳响应头里的 schoolid/domain/area 和最终 index.cgi 页面注释里的
   <ticket-url>/<auth-url>。
2. 把 ticket-url 问号后的参数抄进 ticket_params（IP/MAC 用 {ip}/{mac} 占位）。
3. 若 detect_host 未知，查 DHCP 客户端或抓包看未认证 HTTP 请求被劫持到哪里。

## 说明与风险提示

- 本客户端仅做本机认证，不改动服务端任何规则。NAT 软路由拓扑下，服务端看到的是软路由这一台设备；
  多设备共享属于校园网服务条款范畴，请自行遵守学校规定。
- 会话算法 .so 由 portal 每次下发，本程序自动提取到 /var/lib/esurfing-lite/protect.so，不参与网络之外的任何分发。
- 学校升级 portal 后若协议变化，用 --debug 抓取交互细节，比对本文档的协议描述即可定位。
