#!/usr/bin/env python3

from scapy.all import sr, srp, Ether, IP, ARP, TCP, UDP, ICMP
import ipaddress
import logging
logging.getLogger("scapy").setLevel(logging.ERROR)
import threading
from multiprocessing import Pool
from utils.utils import is_cidr

__hosts = list()

def syn_ping(ip, timeout, retries, results):
    ip_packet = IP(dst=str(ip))
    tcp_packet = TCP(sport=30000, dport=443, flags="S")

    packet = ip_packet / tcp_packet

    ans, _ = sr(packet, timeout=timeout, retry=retries, verbose=False)
    
    for _, received_packet in ans:
        results.add(received_packet[IP].src)

def ack_ping(ip, timeout, retries, results):
    ip_packet = IP(dst=str(ip))
    tcp_packet = TCP(sport=30000, dport=80, flags="A")

    packet = ip_packet / tcp_packet

    ans, _ = sr(packet, timeout=timeout, retry=retries, verbose=False)
    
    for _, received_packet in ans:
        results.add(received_packet[IP].src)

def udp_ping(ip, timeout, retries, results):
    ip_packet = IP(dst=str(ip))
    udp_packet = UDP(sport=30000, dport=40125)

    packet = ip_packet / udp_packet

    ans, _ = sr(packet, timeout=timeout, retry=retries, verbose=False)
    
    for _, received_packet in ans:
        results.add(received_packet[IP].src)

def icmp_echo_ping(ip, timeout, retries, results):
    ip_packet = IP(dst=str(ip))
    icmp_packet = ICMP()

    packet = ip_packet / icmp_packet

    ans, _ = sr(packet, timeout=timeout, retry=retries, verbose=False)

    for _, received_packet in ans:
        results.add(received_packet[IP].src)

def icmp_timestamp_ping(ip, timeout, retries, results):    
    ip_packet = IP(dst=str(ip))
    icmp_packet = ICMP(type=13)

    packet = ip_packet / icmp_packet

    ans, _ = sr(packet, timeout=timeout, retry=retries, verbose=False)

    for _, received_packet in ans:
        results.add(received_packet[IP].src)

def arp_ping(ip, timeout, retries, results):
    ether_packet = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_packet = ARP(pdst=str(ip))

    packet = ether_packet / arp_packet

    ans, _ = srp(packet, timeout=timeout, retry=retries, verbose=False)
    
    for _, received_packet in ans:
        results.add(received_packet[ARP].psrc)

def host_discovery(ip, discovery_config):
    results = set()
    threads = list()

    timeout = discovery_config.get_timeout()
    retries = discovery_config.get_retries()

    if discovery_config.tcp_syn_enabled():
        syn_thread = threading.Thread(target=syn_ping, args=(ip, timeout, retries, results))
        syn_thread.start()
        threads.append(syn_thread)
    
    if discovery_config.tcp_ack_enabled():
        ack_thread = threading.Thread(target=ack_ping, args=(ip, timeout, retries, results))
        ack_thread.start()
        threads.append(ack_thread)

    if discovery_config.udp_ping_enabled():
        udp_thread = threading.Thread(target=udp_ping, args=(ip, timeout, retries, results))
        udp_thread.start()
        threads.append(udp_thread)
    
    if discovery_config.echo_icmp_enabled():
        icmp_echo_thread = threading.Thread(target=icmp_echo_ping, args=(ip, timeout, retries, results))
        icmp_echo_thread.start()
        threads.append(icmp_echo_thread)

    if discovery_config.timestamp_icmp_enabled():
        icmp_timestamp_thread = threading.Thread(target=icmp_timestamp_ping, args=(ip, timeout, retries, results))
        icmp_timestamp_thread.start()
        threads.append(icmp_timestamp_thread)

    if discovery_config.arp_ping_enabled():
        arp_thread = threading.Thread(target=arp_ping, args=(ip, timeout, retries, results))
        arp_thread.start()
        threads.append(arp_thread)

    for thread in threads:
        thread.join()

    return results

def __update_active_hosts(results):
    __hosts.append(results)

def get_active_hosts():
    return __hosts

def __clear_active_hosts():
    __hosts.clear()

def process_results(results):
    for result in results: # Discard empty results
        if result:
            if len(result) == 1: # In case a result set comes, to edit the set
                __update_active_hosts(next(iter(result)))
            else: # In case only one host has been scanned
                 __update_active_hosts(result)

def print_hosts(hosts):
    for host in hosts:
        print(f"Host {host} is up")

    print(f"\nTotal hosts up: {len(hosts)}")

def begin_host_scan(discovery_config):
    ip = discovery_config.get_target()
    number_of_threads = discovery_config.get_threads()

    __clear_active_hosts()

    if is_cidr(ip):
        network = ipaddress.ip_network(ip)
        
        with Pool(processes=number_of_threads) as pool:
            host_discovery_args = [(host, discovery_config) for host in network.hosts()]
            results = pool.starmap(host_discovery, host_discovery_args)

        process_results(results)
    else:
        process_results(host_discovery(ip, discovery_config))