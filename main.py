#!/usr/bin/env python3

from utils.arg_parse_utils import get_host_discovery_args, get_port_scanning_args, get_service_scan, get_os_detection
from utils.utils import check_admin_rights
from host_discovery import *
from port_scanner import *
from banner_grabbing import *
import subprocess

def print_results(ports):
    if ports == None:
        return

    headers = ["PORT", "STATE", "SERVICE", "VERSION"]

    print("\n{:<10} {:<15} {:<10} {:<50}".format(*headers))

    for port in ports:
        port_name = f"{port.number}/{port.protocol}".replace("\r", "")
        port_state = port.state.replace("\r", "")
        port_service = ""
        port_version = ""

        if port.service != None:
            port_service = port.service.replace("\r", "")

            if port.version != None:
                port_version = port.version.replace("\r", "")
        
        data = [port_name, port_state, port_service, port_version]
        print("{:<10} {:<15} {:<10} {:<50}".format(*data))

def start_host_discovery():
    host_discovery_config = get_host_discovery_args()
    port_scanning_config = get_port_scanning_args()

    if not host_discovery_config.skip_host_discovery():
        begin_host_scan(host_discovery_config)
        print_hosts(get_active_hosts())

    if not port_scanning_config.skip_port_scanning():
        begin_port_scan(port_scanning_config)

        ports = None
        if get_service_scan():
            ports = grab_banner(host_discovery_config.get_target(), get_ports())
        else:
            ports = get_ports()

        print_results(ports)

    if get_os_detection():
        command = ['ping', '-c', '1', host_discovery_config.get_target()]
        process = subprocess.run(command, stdout=subprocess.PIPE, text=True)
        ttl = re.search(r'ttl=(\d+)', process.stdout)

        if ttl:
            ttl = int(ttl.group(1))
            
            if ttl > 64 and ttl <= 128:
                print("\nRunning: Windows")
            elif (ttl > 0 and ttl <= 64) or (ttl > 128 and ttl <= 255):
                print("\nRunning: Linux/Unix")
        else:
            print("\nError obtaining the target operating system")

def main():
    check_admin_rights()
    start_host_discovery()

if __name__ == "__main__":
    main()