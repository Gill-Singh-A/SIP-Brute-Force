#! /usr/bin/env python3

from datetime import date
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
        except:
            display('-', f"Error Loading Passwords from File {Back.YELLOW}{arguments.password}{Back.RESET}")
            exit(0)
    if not arguments.ip and not arguments.capture_file:
        display('-', "Please Provide a List of IP Addresses or Network Packet Capture File")
        exit(0)
    elif arguments.capture_file:
        pass
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