#!/usr/bin/env python3

import os
import ctypes
import sys

def check_admin_rights():
    if os.name == "nt": # Windows
        if ctypes.windll.shell32.IsUserAnAdmin() != 0:
            print("The script must be run with administrator permissions.")
            sys.exit(1)
    elif os.name == "posix": # Linux
        if os.getuid() != 0:
            print("The script must be run with administrator permissions.")
            sys.exit(1)

def is_cidr(input):
    return '/' in input