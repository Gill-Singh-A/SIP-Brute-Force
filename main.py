#! /usr/bin/env python3

from scapy.all import *
from hashlib import md5
from pickle import dump
from datetime import date
from base64 import b64decode
from multiprocessing import Lock, Pool, cpu_count
from optparse import OptionParser
from colorama import Fore, Back, Style
from time import strftime, localtime, time

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

if __name__ == "__main__":
    arguments = get_arguments(('-i', "--ip", "ip", "File Name of List of IP Addresses (Seperated by ',', either File Name or IP itself)"),
                              ('-C', "--capture-file", "capture_file", "Packet Capture Files (Seperated by ',')"),
                              ('-D', "--capture-file-data", "capture_file_data", "Dump Data Extracted from Capture File in Pickle Format (Optional)"),
                              ('-u', "--user", "user", "Username for Brute Force (Seperated by ',', either File Name or User itself)"),
                              ('-p', "--password", "password", "Password For Brute Force (Seperated by ',', either File Name or Password itself)"),
                              ('-w', "--write", "write", "Name of the CSV File for the Successfully Logged In IPs to be dumped (default=current data and time)"))
    if not arguments.write:
        arguments.write = f"{date.today()} {strftime('%H_%M_%S', localtime())}.csv"
    if not arguments.password:
        display('*', f"No {Back.MAGENTA}PASSWORD{Back.RESET} Specified")
        display(':', f"Setting Password to {Back.MAGENTA}Blank{Back.RESET}")
        arguments.password = ['']
    else:
        try:
            with open(arguments.password, 'rb') as file:
                display(':', f"Loading Passwords from File {Back.MAGENTA}{arguments.password}{Back.RESET}")
                arguments.password = [password for password in file.read().decode(errors="ignore").split('\n')]
                display('+', f"Passwords Loaded = {Back.MAGENTA}{len(arguments.password)}{Back.RESET}")
        except FileNotFoundError:
            arguments.password = [password for password in arguments.password.split(',')]
        except OSError:
            arguments.password = [password for password in arguments.password.split(',')]
        except MemoryError:
            display('-', f"File {Back.MAGENTA}{arguments.password}{Back.RESET} too big to load!")
            exit(0)
        except Exception as error:
            display('-', f"Error Loading Passwords from File {Back.YELLOW}{arguments.password}{Back.RESET} => {Back.YELLOW}{error}{Back.RESET}")
            exit(0)
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
            except:
                display('-', f"Error Loading IPs from File {Back.YELLOW}{arguments.ip}{Back.RESET}")
                exit(0)
        if not arguments.user:
            display('*', f"No {Back.MAGENTA}USER{Back.RESET} Specified")
            display(':', f"Trying to Find {Back.MAGENTA}Unauthorized Access{Back.RESET}")
            arguments.user = ['']
        else:
            try:
                with open(arguments.user, 'r') as file:
                    display(':', f"Loading Users from File {Back.MAGENTA}{arguments.user}{Back.RESET}")
                    arguments.user = [user for user in file.read().split('\n')]
                    display('+', f"Users Loaded = {Back.MAGENTA}{len(arguments.user)}{Back.RESET}")
            except FileNotFoundError:
                arguments.user = [user for user in arguments.user.split(',')]
            except OSError:
                arguments.user = [user for user in arguments.user.split(',')]
            except:
                display('-', f"Error Loading Users from File {Back.YELLOW}{arguments.user}{Back.RESET}")
                exit(0)
        details = []
        for user in arguments.user:
            for password in arguments.password:
                details.extend([{"ip": ip, "user": user, "password": password} for ip in ips])
    if len(successful_logins) > 0:
        display(':', f"Dumping Successfully Authorized IP Addresses in file {Back.MAGENTA}{arguments.write}{Back.RESET}", start='\n')
        with open(arguments.write, 'w') as file:
            file.write("User,Password,IP\n")
            file.write('\n'.join([f"{login['user']},{login['password']},{login['ip']}" for login in successful_logins]))
        display('+', f"Dumped Successfully Authorized IP Addresses in file {Back.MAGENTA}{arguments.write}{Back.RESET}")