脚本用systemd来控制shadowsocks-libev的多进程，可以使用多个配置文件，以便开放多个端口。

使用方法:
---
将写好的多个配置文件放到```/etc/shadowsocks-libev/```目录下，脚本会遍历里面的配置文件，依次使用systemd管理进程。

Python脚本（需使用Python3，推荐）：
	
    python3 ss.py start|restart|stop|enable|disable|status        #启动|重启|停止|开机启动|禁止开机启动|状态
    
bash脚本：

	ss.sh start|restart|stop|enable|disable|status		#启动|重启|停止|开机启动|禁止开机启动|状态

    
仅在Ubuntu 16.04上测试过，其他发行版请自行根据情况修改脚本。