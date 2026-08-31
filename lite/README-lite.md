# esurfing_lite — 干净实现的天翼校园认证客户端（Beta）

依据对官方 ESurfingSvr 2.4-64 的反汇编分析重写，只做认证/保活/下线，
**不包含**官方客户端的共享检测组件（CWiFiSharedValidate：ps -C 进程检查 +
ip_forward 检查），心跳里也永远不发送 <shared>1</shared>。

## 与原版协议的对应关系（逆向结论）

| 官方组件                        | 本实现                                |
|---------------------------------|---------------------------------------|
| config.campus.js.chinatelecom.com / portal 页面 | detect() + get_config()（解析 ticket-url/auth-url） |
| zxmAlogic.zxm -> protect.so     | ZsmCodec：解析 zxm 头 -> 逆 XOR -> LZMA1 解压 -> ctypes 调 Code/Prepare/FreeResult |
| CDC-Checksum                    | MD5(编码串).upper()                    |
| MakeTicket/Auth/Keep/TermRequestData | 同结构的 XML 模板                      |
| CWiFiSharedValidate             | **不存在**（这就是"绕过共享检测"的关键） |

## 安装（Debian 13）

    sudo cp esurfing_lite.py /usr/local/bin/esurfing-lite
    sudo chmod 755 /usr/local/bin/esurfing-lite
    sudo cp esurfing-lite.service /etc/systemd/system/
    sudo cp lite.conf.example /etc/esurfing/lite.conf
    sudo nano /etc/esurfing/lite.conf        # 填 user/pass，按需改 detect_url
    sudo systemctl daemon-reload
    sudo systemctl enable --now esurfing-lite
    journalctl -u esurfing-lite -f

## 前提：算法文件 zxmAlogic.zxm

官方 2.4-64 的编解码算法是一个**服务端下发的动态库**（LZMA 压缩、带 3 段头）。
本程序不内置算法，而是复用官方客户端下载的 /usr/local/ESurfing/bin/zxmAlogic.zxm
（先用本包 install.sh 装一次官方守护进程并成功拨号一次即可得到该文件）。

## 测试

    # 前台单次拨号（详细日志）
    sudo python3 esurfing_lite.py --config /etc/esurfing/lite.conf --once --debug

## 已知风险 / 局限性（重要）

1. 各校 portal 细节可能不同（有的学校从 config 服务器下发配置、有的在重定向页里）。
   如果自动获取 ticket-url/auth-url 失败，请按 lite.conf.example 手动指定，
   值可以从官方客户端抓包（tcpdump 看 /ticket.cgi、/auth.cgi 的 Host）得到。
2. Prepare 的第一个参数沿用了官方的传法（zxm 头部的 3 字节 magic 指针）；
   若个别算法版本不接受，请反馈日志。
3. 这是 Beta：请先 --once --debug 验证能认证成功，再切换为系统服务。
