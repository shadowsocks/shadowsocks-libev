#!/usr/bin/env python3
#-*- coding:utf-8 -*-

import sys, subprocess, os

commands = 'start restart stop enable disable status'.split()
if len(sys.argv) != 2 or sys.argv[1] not in commands:
    print('Usage: ss.py {}'.format('|'.join(commands)))
else:
    conf_dir = '/etc/shadowsocks-libev/'
    filenames = [
        os.path.splitext(filename)[0] for filename in os.listdir(conf_dir)
        if os.path.splitext(filename)[1] == '.json'
        and os.path.isfile(conf_dir + filename)
    ]
    for name in filenames:
        command = "systemctl {} shadowsocks-libev-server@{}".format(
            sys.argv[1], name)
        try:
            subprocess.call(command.split(), shell=False)
        except Exception as e:
            print(e)