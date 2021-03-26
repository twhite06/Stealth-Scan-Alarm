#!/usr/bin/python3

from scapy.all import *
import argparse
import base64

incident = 0 
username = ""
password = ""

def packetcallback(packet):
  try:
    global incident
    global username
    global password
    if packet[TCP].flags == 0:
      incident = incident+1
      ip = packet[IP].src
      port = packet[TCP].sport
      print("ALERT #", incident, " NULL scan is detected from", ip, "(", port, ")")
    if packet[TCP].flags == "FPU":
      incident = incident+1
      ip = packet[IP].src
      port = packet[TCP].sport
      print("ALERT #", incident, " XMAS scan is detected from", ip, "(", port, ")")
    if packet[TCP].flags == "F":
      incident = incident+1
      ip = packet[IP].src
      port = packet[TCP].sport
      print("ALERT #", incident, " FIN scan is detected from", ip, "(", port, ")")
    if packet[TCP].dport == 80:
      packetInfo = packet[Raw].load.decode("ascii").strip()
      Nikto = packetInfo.find("Nikto")
      if Nikto != -1:
        incident = incident+1
        ip = packet[IP].src
        port = packet[TCP].sport
        print("ALERT #", incident, " Nikto scan is detected from", ip, "(", port, ")") 
        print(*50)
      result = packetInfo.find("Authorization: Basic")
      if result != -1:
        info = packetInfo[result+21:]
        temp = info.find("Accept-Encoding")
        if temp != -1:
          A_Einfo = info[:temp]
          base64_bytes = A_Einfo.encode('ascii')
          message_bytes = base64.b64decode(base64_bytes)
          UserPass = message_bytes.decode('ascii')
          incident = incident+1
        else:
          base64_bytes = info.encode('ascii')
          message_bytes = base64.b64decode(base64_bytes)
          UserPass = message_bytes.decode('ascii')      
          incident = incident+1
      colonIndex = UserPass.find(":")
      username = UserPass[:colonIndex-1]
      password = UserPass[colonIndex+1:]
      print("ALERT #", incident, "Usernames and passwords sent in the clear (HTTP) (username:", username, ", password:", password,")")
      print ("=" * 50)      
    if packet[TCP].dport == 21:
      packetInfo = packet[Raw].load.decode("ascii").strip()
      result = packetInfo.find("USER")
      if result != -1:
        username = packetInfo[result+5:]
      result = packetInfo.find("PASS")
      if result != -1:
        incident = incident+1
        password = packetInfo[result+5:]
        print("ALERT #", incident, "Usernames and passwords sent in the clear (FTP) (username:", username, ", password:", password,")")
        print ("=" * 50)
    if packet[TCP].dport == 445:
      incident = incident+1
      ip = packet[IP].src
      port = packet[TCP].sport
      print("ALERT #", incident, " SMB Protocol scan is detected from", ip, "(", port, ")")
      print(*50)
    # NiktoCheck = packet[Raw].load.decode("ascii").strip()
    # Nikto = NiktoCheck.find("Nikto")
    # print(Nikto)
    # if Nikto != -1:
    #   incident = incident+1
    #   ip = packet[IP].src
    #   port = packet[TCP].sport
    #   print("ALERT #", incident, " Nikto scan is detected from", ip, "(", port, ")") 
    #   print(*50)
  except:
    pass


parser = argparse.ArgumentParser(description='A network sniffer that identifies basic vulnerabilities')
parser.add_argument('-i', dest='interface', help='Network interface to sniff on', default='eth0')
parser.add_argument('-r', dest='pcapfile', help='A PCAP file to read')
args = parser.parse_args()
if args.pcapfile:
  try:
    print("Reading PCAP file %(filename)s..." % {"filename" : args.pcapfile})
    sniff(offline=args.pcapfile, prn=packetcallback)    
  except:
    print("Sorry, something went wrong reading PCAP file %(filename)s!" % {"filename" : args.pcapfile})
else:
  print("Sniffing on %(interface)s... " % {"interface" : args.interface})
  try:
    sniff(iface=args.interface, prn=packetcallback)
  except:
    print("Sorry, can\'t read network traffic. Are you root?")
