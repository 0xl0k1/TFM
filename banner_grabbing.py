#!/usr/bin/env python3

import socket
import re
import dns.resolver
import dns.exception

def grab_ftp_banner(sock):
    response = sock.recv(1024).decode("utf-8")
    ftp_version = re.search(r"([a-zA-Z]+[a-zA-Z\d]*\s*\d+\.\d+\.\d+)", response)
    return ftp_version.group(1)

def grab_ssh_banner(sock):
    response = sock.recv(1024).decode("utf-8")

    protocol_version_match = re.search(r"SSH-(\d\.\d)", response)
    protocol_version = protocol_version_match.group(1) if protocol_version_match else ""

    formatted_string = re.sub(r"SSH-\d\.\d-", "", response)
    formatted_string = re.sub(r"_", " ", formatted_string)
    formatted_string = re.sub(r"-", " ", formatted_string)
    formatted_string = formatted_string.strip()

    return f"{formatted_string} (protocol {protocol_version})"

def grab_smtp_banner(sock):
    response = sock.recv(1024).decode("utf-8")
    match = re.search(r'(ESMTP.*?\))', response)
    if match:
        return match.group(0)

def grab_dns_banner(host):
    resolver = dns.resolver.Resolver()
    resolver.nameservers = [host]
    resolver.timeout = 5
    resolver.lifetime = 5

    try:
        answer = resolver.resolve("version.bind", "TXT", "CH")

        for rdata in answer:
            version = rdata.strings[0].decode("utf-8")

            if "BIND" in version:
                return version  # If the response already contains 'BIND', return as is
            return f"ISC BIND {version}"  # Formatting the response
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
        return "DNS version could not be obtained"
    except Exception as e:
        return f"Error: {str(e)}"
    
def grab_http_banner(sock, host):
    sock.send(b'GET / HTTP/1.1\r\nHost: ' + host.encode("utf-8") + b'\r\n\r\n')
    banner = sock.recv(1024).decode()

    match = re.search(r'Server: (.*)', banner)
    if match:
        return match.group(1)
    
def grab_mysql_banner(sock):
    try:
        data = sock.recv(256).decode('utf-8', 'ignore')
        sock.close()

        # Find the index of the newline character, which marks the start of the version
        inicio = data.find('\n') + 1
        # Finding the index of the first null character after the beginning of the version
        fin = data.find('\x00', inicio)
        # Extract and return version
        return f"MySQL {data[inicio:fin]}"
    except Exception as _:
        return None

def test_bind_shell(sock):
    whoami_command = "whoami\n"
    sock.sendall(whoami_command.encode())

    data = sock.recv(1024).decode()
    
    if "root" in data:
        return True

    return False

def grab_smb_banner(sock):
    negotiation_message = (
            b"\x00\x00\x00\x85\xff\x53\x4d\x42\x72\x00\x00\x00\x00\x18\x53\xc8"
            b"\x17\x02\x00\xe3\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\xfe\xda\x00\x7b\x03\x02\x00\x01\x00\x04\x41\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x2f\x00\x00\x00\x00\x02"
            b"\x02\x10\x02\x00\x03\x02\x03\x11\x03\x00\x00\x01\x00\x26\x00\x00"
            b"\x00\x00\x00\x01\x00\x20\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00"
        )
        
    sock.send(negotiation_message)
    response = sock.recv(1024)

    if response[4:8] == b'\xffSMB':
        return "Samba SMB1"
    elif response[4:8] == b'\xfeSMB':
        return "Samba SMB2/3"
    
def grab_other_banner(sock):
    response = sock.recv(1024).decode("utf-8")
    return response

def grab_banner(host, ports):
    for port in ports:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            try:
                sock.settimeout(10)
                sock.connect((host, port.number))
                
                if port.number in [21, 2121]:
                    port.service = "ftp"
                    port.version = grab_ftp_banner(sock)
                elif port.number == 22:
                    port.service = "ssh"
                    port.version = grab_ssh_banner(sock)
                elif port.number == 23:
                    port.service = "telnet"
                elif port.number == 25:
                    port.service = "smtp"
                    port.version = grab_smtp_banner(sock)
                elif port.number == 53:
                    port.service = "dns"
                    port.version = grab_dns_banner(host)
                elif port.number in [80, 8180]:
                    port.service = "http"
                    port.version = grab_http_banner(sock, host)
                elif port.number in [139, 445]:
                    port.service = "smb"
                    port.version = grab_smb_banner(sock)
                elif port.number == 3306:
                    port.service = "mysql"
                    port.version = grab_mysql_banner(sock)
                else:
                    if test_bind_shell(sock):
                        port.service = "bindshell"
                        port.version = "Root shell"
                    else:
                        port.version = grab_other_banner(sock)
            except socket.timeout:
                pass
            except socket.error as _:
                # Handle connection errors
                pass
            except Exception as _:
                # Handle other errors
                pass
            finally:
                sock.close()
    
    return ports