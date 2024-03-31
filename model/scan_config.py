#!/usr/bin/env python3

class HostDiscoveryConfig:
    def __init__(self, target, threads, timeout, retries, skip, tcp_syn, tcp_ack, udp_ping, echo_icmp, timestamp_icmp, arp_ping):
        self.target = target
        self.threads = threads
        self.timeout = timeout
        self.retries = retries
        self.skip = skip
        self.tcp_syn = tcp_syn
        self.tcp_ack = tcp_ack
        self.udp_ping = udp_ping
        self.echo_icmp = echo_icmp
        self.timestamp_icmp = timestamp_icmp
        self.arp_ping = arp_ping

    def get_target(self):
        return self.target
    
    def get_threads(self):
        return self.threads
    
    def get_timeout(self):
        return self.timeout
    
    def get_retries(self):
        return self.retries
    
    def skip_host_discovery(self):
        return self.skip

    def tcp_syn_enabled(self):
        return self.tcp_syn

    def tcp_ack_enabled(self):
        return self.tcp_ack

    def udp_ping_enabled(self):
        return self.udp_ping

    def echo_icmp_enabled(self):
        return self.echo_icmp

    def timestamp_icmp_enabled(self):
        return self.timestamp_icmp
    
    def arp_ping_enabled(self):
        return self.arp_ping
    
class PortScannerConfig:
    def __init__(self, target, ports, threads, timeout, retries, skip, stealth, tcp_connect, fin, xmas, null, ack):
        self.target = target
        self.ports = ports
        self.threads = threads
        self.timeout = timeout
        self.retries = retries
        self.skip = skip
        self.stealth = stealth
        self.tcp_connect = tcp_connect
        self.fin = fin
        self.xmas = xmas
        self.null = null
        self.ack = ack

    def get_target(self):
        return self.target
    
    def get_ports(self):
        return self.ports
    
    def get_threads(self):
        return self.threads
    
    def get_timeout(self):
        return self.timeout
    
    def get_retries(self):
        return self.retries
    
    def skip_port_scanning(self):
        return self.skip

    def stealth_scan_enabled(self):
        return self.stealth

    def tcp_connect_scan_enabled(self):
        return self.tcp_connect
    
    def fin_scan_enabled(self):
        return self.fin
    
    def xmas_scan_enabled(self):
        return self.xmas
    
    def null_scan_enabled(self):
        return self.null
    
    def ack_scan_enabled(self):
        return self.ack