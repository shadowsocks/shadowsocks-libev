#/bin/sh

if test $# -ne 0
then
        if test "$1" == "start"
        then
                for file in /etc/shadowsocks-libev/*
                do
                        name=$(basename $file .json)
                        systemctl start shadowsocks-libev-server@$name
                done
        elif [ "$1" == "stop" ]
        then
                for file in /etc/shadowsocks-libev/*
                do
                        name=$(basename $file .json)
                        systemctl stop shadowsocks-libev-server@$name
                done
        elif [ "$1" == "restart" ]
        then
                for file in /etc/shadowsocks-libev/*
                do
                        name=$(basename $file .json)
                        systemctl restart shadowsocks-libev-server@$name
                done
        elif [ "$1" == "enable" ]
        then
                for file in /etc/shadowsocks-libev/*
                do
                        name=$(basename $file .json)
                        systemctl enable shadowsocks-libev-server@$name
                done
        elif [ "$1" == "disable" ]
        then
                for file in /etc/shadowsocks-libev/*
                do
                        name=$(basename $file .json)
                        systemctl disable shadowsocks-libev-server@$name
                done
        elif [ "$1" == "status" ]
        then
                for file in /etc/shadowsocks-libev/*
                do
                        name=$(basename $file .json)
                        systemctl status shadowsocks-libev-server@$name
                done
        else
                echo "Usage:ss.sh start|stop|restart|enable"
        fi
else
        echo "Usage:ss.sh start|stop|restart|enable"
fi

