#!/usr/bin/env python3

from scapy.all import sr, sr1, IP, TCP, ICMP
import logging
logging.getLogger("scapy").setLevel(logging.ERROR)
import threading
from multiprocessing import Pool
from model.port import Port

__ports = list()
__found_ports = list()

def syn_scan(ip, port, timeout, retries, results):
    ip_packet = IP(dst=ip)
    tcp_packet = TCP(sport=30000, dport=port, flags="S")

    packet = ip_packet / tcp_packet

    ans, _ = sr(packet, timeout=timeout, retry=retries, verbose=False)
    
    for sent_packet, received_packet in ans:
        if received_packet.haslayer(TCP) and received_packet.getlayer(TCP).flags == "SA":
            if not sent_packet[TCP].dport in __found_ports:
                __found_ports.append(sent_packet[TCP].dport)
                results.add(Port(sent_packet[TCP].dport, "tcp", "open", None, None))
                
def tcp_scan(ip, port, timeout, retries, results):
    ip_packet = IP(dst=ip)
    tcp_packet = TCP(sport=30000, dport=port, flags="S")

    packet = ip_packet / tcp_packet

    ans, _ = sr(packet, timeout=timeout, retry=retries, verbose=False)
    
    for _, received_packet in ans:
        if received_packet.haslayer(TCP) and received_packet.getlayer(TCP).flags == "SA":
            tcp = TCP(sport=30000, dport=port, seq=received_packet[TCP].ack, flags="A")
            packet2 = ip_packet / tcp

            ans2, _ = sr(packet2, timeout=timeout, retry=retries, verbose=False)
            
            for sent_packet2, received_packet2 in ans2:
                if received_packet2.haslayer(TCP) and received_packet2.getlayer(TCP).flags == "R":
                    if not sent_packet2[TCP].dport in __found_ports:
                        __found_ports.append(sent_packet2[TCP].dport)
                        results.add(Port(sent_packet2[TCP].dport, "tcp", "open", None, None))
                        
def fin_scan(ip, port, timeout, retries, results):
    ip_packet = IP(dst=ip)
    tcp_packet = TCP(sport=30000, dport=port, flags="F")

    packet = ip_packet / tcp_packet

    ans = sr1(packet, timeout=timeout, retry=retries, verbose=False)

    if ans is None:
        if not port in __found_ports:
            __found_ports.append(port)
            results.add(Port(port, "tcp", "open|filtered", None, None))
    elif ans.haslayer(TCP) and ans.getlayer(TCP).flags == "RA": # Closed port
        pass
    elif ans.haslayer(ICMP) and int(ans.getlayer(ICMP).type) == 3 and int(ans.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]: # Filtered port - ICMP responses of type 3 code 1, 2, 3, 9, 10, or 13 indicate filtering
        if not port in __found_ports:
            __found_ports.append(port)
            results.add(Port(port, "tcp", "filtered", None, None))
            
def xmas_scan(ip, port, timeout, retries, results):
    ip_packet = IP(dst=ip)
    tcp_packet = TCP(sport=30000, dport=port, flags="FPU")

    packet = ip_packet / tcp_packet

    ans = sr1(packet, timeout=timeout, retry=retries, verbose=False)

    if ans is None:
        if not port in __found_ports:
            __found_ports.append(port)
            results.add(Port(port, "tcp", "open|filtered", None, None))
    elif ans.haslayer(TCP) and ans.getlayer(TCP).flags == "RA": # Closed port
        pass
    elif ans.haslayer(ICMP) and int(ans.getlayer(ICMP).type) == 3 and int(ans.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]: # Filtered port - ICMP responses of type 3 code 1, 2, 3, 9, 10, or 13 indicate filtering
        if not port in __found_ports:
            __found_ports.append(port)
            results.add(Port(port, "tcp", "filtered", None, None))
            
def null_scan(ip, port, timeout, retries, results):
    ip_packet = IP(dst=ip)
    tcp_packet = TCP(sport=30000, dport=port, flags="")

    packet = ip_packet / tcp_packet

    ans = sr1(packet, timeout=timeout, retry=retries, verbose=False)

    if ans is None:
        if not port in __found_ports:
            __found_ports.append(port)
            results.add(Port(port, "tcp", "open|filtered", None, None))
    elif ans.haslayer(TCP) and ans.getlayer(TCP).flags == "RA": # Closed port
        pass
    elif ans.haslayer(ICMP) and int(ans.getlayer(ICMP).type) == 3 and int(ans.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]: # Filtered port - ICMP responses of type 3 code 1, 2, 3, 9, 10, or 13 indicate filtering
        if not port in __found_ports:
            __found_ports.append(port)
            results.add(Port(port, "tcp", "filtered", None, None))

def ack_scan(ip, port, timeout, retries, results):
    ip_packet = IP(dst=ip)
    tcp_packet = TCP(sport=30000, dport=port, flags="A")

    packet = ip_packet / tcp_packet

    ans = sr1(packet, timeout=timeout, retry=retries, verbose=False)

    if ans is None: # Filtered port (no response)
        if not port in __found_ports:
            __found_ports.append(port)
            results.add(Port(port, "tcp", "filtered", None, None))
    elif ans.haslayer(TCP) and ans.getlayer(TCP).flags == "R": # Port is not filtered
        pass
    elif ans.haslayer(ICMP) and int(ans.getlayer(ICMP).type) == 3 and int(ans.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]: # Filtered port - ICMP responses of type 3 code 1, 2, 3, 9, 10, or 13 indicate filtering
        if not port in __found_ports:
            __found_ports.append(port)
            results.add(Port(port, "tcp", "filtered", None, None))

def port_scan(ip, port, port_scan_config):
    results = set()
    threads = list()

    timeout = port_scan_config.get_timeout()
    retries = port_scan_config.get_retries()

    if port_scan_config.stealth_scan_enabled():
        syn_scan_thread = threading.Thread(target=syn_scan, args=(ip, port, timeout, retries, results))
        syn_scan_thread.start()
        threads.append(syn_scan_thread)

    if port_scan_config.tcp_connect_scan_enabled():
        tcp_connect_scan_thread = threading.Thread(target=tcp_scan, args=(ip, port, timeout, retries, results))
        tcp_connect_scan_thread.start()
        threads.append(tcp_connect_scan_thread)

    if port_scan_config.fin_scan_enabled():
        fin_scan_thread = threading.Thread(target=fin_scan, args=(ip, port, timeout, retries, results))
        fin_scan_thread.start()
        threads.append(fin_scan_thread)
    
    if port_scan_config.xmas_scan_enabled():
        xmas_scan_thread = threading.Thread(target=xmas_scan, args=(ip, port, timeout, retries, results))
        xmas_scan_thread.start()
        threads.append(xmas_scan_thread)
    
    if port_scan_config.null_scan_enabled():
        null_scan_thread = threading.Thread(target=null_scan, args=(ip, port, timeout, retries, results))
        null_scan_thread.start()
        threads.append(null_scan_thread)

    if port_scan_config.ack_scan_enabled():
        ack_scan_thread = threading.Thread(target=ack_scan, args=(ip, port, timeout, retries, results))
        ack_scan_thread.start()
        threads.append(ack_scan_thread)

    for thread in threads:
        thread.join()

    return results

def __update_ports(results):
    __ports.append(results)

def get_ports():
    return __ports

def __clear_ports():
    __ports.clear()

def process_results(results):
    for result in results: # Discard empty results
        if result:
            __update_ports(next(iter(result)))

def begin_port_scan(port_scan_config):
    ip = port_scan_config.get_target()
    ports = port_scan_config.get_ports()
    number_of_threads = port_scan_config.get_threads()

    __clear_ports()
    
    with Pool(processes=number_of_threads) as pool:
        port_scan_args = [(ip, port, port_scan_config) for port in ports]
        results = pool.starmap(port_scan, port_scan_args)

    process_results(results)