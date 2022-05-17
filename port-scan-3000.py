#requried imports
import socket
import sys
import queue
import threading
import ipaddress
import pyfiglet
from datetime import datetime

#create ascii banner
banner = pyfiglet.figlet_format('Port-Scan 3000')
print('-' * 75)
print(banner)
print('-' * 75)

#take in IP of target
target = input(str('Enter the target IP: '))

#function for validating IP address
def validate_ip_address(address):
    try:
        ip = ipaddress.ip_address(address)
        return True
    except ValueError:
        return False

#check if input is a valid IP address; if not quit program
if validate_ip_address(target) == False:
    print('Invalid IP address.')
    quit()

#if IP address is valid, continue with scan
print('Please wait, scanning remote host ' + target)

#start time
start = datetime.now()

#create queue for range of port numbers to scan
q = queue.Queue()
for i in range(1,65535):
    q.put(i)

#header for list of open ports
print('%-20s %-20s %-15s' %('| Port', '| Service', '| Status'))
print('-' * 75)

#list of commonly used ports to display services they provide
portlist = [20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 110, 119, 123, 135, 137, 139, 143, 389, 443, 445, 563, 993, 995]

#scan ports on target machine
def scan():
    while not q.empty():
        port = q.get()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            socket.setdefaulttimeout(0.001)
            try:
                result = sock.connect_ex((target, port))
                if result == 0:
                    if port in portlist:
                        service = socket.getservbyport(port)
                    else:
                        service = '---'
                    print('%-20s %-20s %-15s' %('| ' + str(port), '| ' + service, '| Open'))
                sock.close()
            #exception handling
            except KeyboardInterrupt:
                print('Scan aborted.')
                sys.exit()
            except socket.gaierror:
                print('Hostname could not be resolved.')
                sys.exit()
            except socket.error:
                print('Could not connect to server.')
                sys.exit()
        q.task_done()

#implement threading using 100 threads
for i in range(100):
    t = threading.Thread(target=scan, daemon=True)
    t.start()

#closes out all threads working on the queue
q.join()

#end time
end = datetime.now()

#print total time
totaltime = end - start
print('Scan completed in ' + str(totaltime))
