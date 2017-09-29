This script is used to configure multi-ports using multi-configuration files. It uses systemd to manage multiple shadowsocks-libev processes, so in theory it will work on any Linux distribution that has systemd.

Usage:
---

You need have Python3 installed on your system, you can check it out by using ```python3 --version```.

The usage is pretty simple: just like original systemctl.

1. put your configuration files in ```/etc/shadowsocks-libev/```
2. use commands like systemctl ```ython3 ss.py start|restart|stop|enable|disable|status```