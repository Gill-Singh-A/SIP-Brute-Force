# SIP Brute Force
A Simple Python Program that uses **scapy** and **socket** module for Offline and Online Brute Force attacks against Session Invite Protocol (SIP)
## Requirements
Language Used = Python3
Modules/Packages used:
* socket
* scapy
* hashlib
* pickle
* random
* datetime
* base64
* multiprocessing
* optparse
* colorama
* time
<!-- -->
Install the dependencies:
```bash
pip install -r requirements.txt
```
### Note
When the Protocol for Online Brute Force is **UDP**, mutliprocessing will not work, because the Port at which the Client (our machine) listens would be the same for all threads which would lead to conflict between packets of different threads.