#!/usr/bin/env python3

import argparse
import ipaddress
import sys
from model.scan_config import *

def __get_arguments():
    parser = argparse.ArgumentParser(description="Tool to discover hosts and ports in your local network.", usage='%(prog)s [Scan Type(s)] [Options] target')

    host_discovery_group = parser.add_argument_group("HOST DISCOVERY")
    scan_techniques_group = parser.add_argument_group("SCAN TECHNIQUES")
    port_specification_group = parser.add_argument_group("PORT SPECIFICATION AND SCAN ORDER")
    service_version_detection_group = parser.add_argument_group("SERVICE/VERSION DETECTION")
    os_detection_group = parser.add_argument_group("OS DETECTION")
    timing_performance_group = parser.add_argument_group("TIMING AND PERFORMANCE")

    parser.add_argument(type=__valid_ip_address, dest="target", help="Can pass IP addresses and network ranges")

    timing_performance_group.add_argument("-T", choices=['0', '1', '2', '3', '4', '5'], default='2', dest="intensity", help='Set timing template (higher is faster) <0-5> (Default: 2)')
    timing_performance_group.add_argument("--time-out", type=int, default=1, dest="timeout", help="Give up on target after this long (Default: 1)")
    timing_performance_group.add_argument("--retries", type=int, default=1, dest="retries", help="Caps number of port scan probe retransmissions (Default: 1)")

    host_discovery_group.add_argument("-Pn", action='store_true', dest="skip_host_discovery", help='Treat all hosts as online -- skip host discovery')
    host_discovery_group.add_argument("-PS", action='store_true', dest="tcp_syn_host_discovery", help='TCP SYN discovery')
    host_discovery_group.add_argument("-PA", action='store_true', dest="tcp_ack_host_discovery", help='ACK discovery')
    host_discovery_group.add_argument("-PU", action='store_true', dest="udp_host_discovery", help='UDP discovery')
    host_discovery_group.add_argument("-PE", action='store_true', dest="echo_icmp_host_discovery", help='ICMP echo discovery probe')
    host_discovery_group.add_argument("-PP", action='store_true', dest="timestamp_icmp_host_discovery", help='ICMP timestamp discovery probe')
    host_discovery_group.add_argument("-PR", action='store_true', dest="arp_host_discovery", help='ARP discovery')

    host_discovery_group.add_argument("-sn", action='store_true', dest="skip_port_scanning", help='Ping Scan - disable port scan')
    scan_techniques_group.add_argument("-sS", action='store_true', dest="stealth_scan", help='TCP SYN scan')
    scan_techniques_group.add_argument("-sT", action='store_true', dest="tcp_connect_scan", help='TCP Connect scan')
    scan_techniques_group.add_argument("-sF", action='store_true', dest="fin_scan", help='FIN scan')
    scan_techniques_group.add_argument("-sX", action='store_true', dest="xmas_scan", help='Xmas scan')
    scan_techniques_group.add_argument("-sN", action='store_true', dest="null_scan", help='TCP NULL scan')
    scan_techniques_group.add_argument("-sA", action='store_true', dest="ack_scan", help='ACK scan')

    service_version_detection_group.add_argument("-sV", action='store_true', dest="service_version_detection", help='Probe open ports to determine service/version info')
    os_detection_group.add_argument("-O", action='store_true', dest="os_detection", help='Enable OS detection')

    port_specification_group.add_argument("-p", type=__parse_ports, default="1-65535", dest="ports", help='Only scan specified ports (Default: 1-65535)')

    args = parser.parse_args()
    return args

def __valid_ip_address(ip):
    try:
        ipaddress.ip_address(ip)
        return ip
    except ValueError:
        try:
            # If it fails, try to parse it as a CIDR range.
            ipaddress.ip_network(ip, strict=False)
        except ValueError:
            raise argparse.ArgumentTypeError(f"'{ip}' is not a valid IP address.")
    
    return ip

def __parse_ports(port_input):
    """ Parse port inputs like '1-500' or '1,2,3,4' and return a list of ports. """
    ports = set()

    if port_input == "-":
        for port in range(1, 65535):
            ports.add(port)
        
        return ports

    for part in port_input.split(','):
        if '-' in part:
            # Port range
            try:
                start, end = map(int, part.split('-'))
                if start <= 0 or end <= 0 or end > 65535 or start > end:
                    raise ValueError
                ports.update(range(start, end + 1))
            except ValueError:
                raise argparse.ArgumentTypeError("Invalid range: '{}'".format(part))
        else:
            # Single port
            try:
                port = int(part)
                if port <= 0 or port > 65535:
                    raise ValueError
                ports.add(port)
            except ValueError:
                raise argparse.ArgumentTypeError("Invalid port: '{}'".format(part))

    return list(ports)

def __get_threads():
    intensity_to_threads = {
        '0': 1,
        '1': 10,
        '2': 20,
        '3': 30,
        '4': 40,
        '5': 50
    }

    return intensity_to_threads.get(__get_arguments().intensity)

def get_host_discovery_args():
    target = __get_arguments().target
    threads = __get_threads()
    timeout=__get_arguments().timeout
    retries=__get_arguments().retries

    skip_host_discovery = __get_arguments().skip_host_discovery
    tcp_syn = __get_arguments().tcp_syn_host_discovery
    tcp_ack = __get_arguments().tcp_ack_host_discovery
    udp_ping = __get_arguments().udp_host_discovery
    echo_icmp = __get_arguments().echo_icmp_host_discovery
    timestamp_icmp = __get_arguments().timestamp_icmp_host_discovery
    arp_ping = __get_arguments().arp_host_discovery

    if skip_host_discovery and any([tcp_syn, tcp_ack, udp_ping, echo_icmp, timestamp_icmp, arp_ping]):
        print("Error: Incompatible scan types selected.")
        sys.exit(1)
    elif not any([skip_host_discovery, tcp_syn, tcp_ack, udp_ping, echo_icmp, timestamp_icmp, arp_ping]):
        arp_ping = True

    config = HostDiscoveryConfig(
        target=target,
        threads=threads,
        timeout=timeout,
        retries=retries,
        skip=skip_host_discovery,
        tcp_syn=tcp_syn,
        tcp_ack=tcp_ack,
        udp_ping=udp_ping,
        echo_icmp=echo_icmp,
        timestamp_icmp=timestamp_icmp,
        arp_ping=arp_ping
    )

    return config

def get_port_scanning_args():
    target = __get_arguments().target
    ports = __get_arguments().ports
    threads = __get_threads()
    timeout=__get_arguments().timeout
    retries=__get_arguments().retries

    skip_port_scanning = __get_arguments().skip_port_scanning
    stealth_scan = __get_arguments().stealth_scan
    tcp_connect_scan = __get_arguments().tcp_connect_scan
    fin_scan = __get_arguments().fin_scan
    xmas_scan = __get_arguments().xmas_scan
    null_scan = __get_arguments().null_scan
    ack_scan = __get_arguments().ack_scan

    if skip_port_scanning and any([stealth_scan, tcp_connect_scan, fin_scan, xmas_scan, null_scan, ack_scan]):
        print("Error: Incompatible scan types selected.")
        sys.exit(1)
    elif not any([skip_port_scanning, stealth_scan, tcp_connect_scan, fin_scan, xmas_scan, null_scan, ack_scan]):
        stealth_scan = True
        fin_scan = True
        null_scan = True
        ack_scan = True

    config = PortScannerConfig(
        target=target,
        ports=ports,
        threads=threads,
        timeout=timeout,
        retries=retries,
        skip=skip_port_scanning,
        stealth=stealth_scan,
        tcp_connect=tcp_connect_scan,
        fin=fin_scan,
        xmas=xmas_scan,
        null=null_scan,
        ack=ack_scan
    )

    return config

def get_ports():
    return __get_arguments().ports

def get_service_scan():
    return __get_arguments().service_version_detection

def get_os_detection():
    return __get_arguments().os_detection