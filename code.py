from secrets import SSID, PASSWORD, KNOWN_NODES, MAGIC_NUMBER, HARDCODED_PACKETS
from socket import AF_INET, SOCK_STREAM, socket, getaddrinfo
from binascii import unhexlify, hexlify
from time import sleep, localtime
from network import WLAN, STA_IF
from random import choice
from machine import Pin

from nodeutils import create_header, is_header_valid, SERVICES, create_version, parse_version, parse_invs, create_getdata

led = Pin("LED", Pin.OUT)

wlan = WLAN(STA_IF)
wlan.active(True)
wlan.connect(SSID, PASSWORD)

while not wlan.isconnected():
    print(f"Connecting WiFi device to {SSID}...")
    led.on()
    sleep(0.5)
    led.off()
    sleep(0.5)
    

print(f"WiFi status: {wlan.isconnected()}")

hostport = (choice(KNOWN_NODES), 8333)
print(f"Connecting to {hostport}")

sock = socket(AF_INET, SOCK_STREAM)
sock.settimeout(10)
sock.connect(hostport)

# VERSION MESSAGE
version_payload = create_version(70015, hostport, "/picotoshi:0.1/")
version_header = create_header(version_payload, "version")
version = MAGIC_NUMBER + version_header + version_payload
sock.send(version)

input_msg_array = []
buffer = b''

while wlan.isconnected():
    data = buffer + sock.recv(1024)
    buffer_pointer = data.rfind(MAGIC_NUMBER)
    buffer = data[buffer_pointer:]
    
    for msg in data[:buffer_pointer].split(MAGIC_NUMBER):
        if len(msg) > 0 and is_header_valid(msg):
            input_msg_array.append(msg)
    
    while len(input_msg_array) > 0:
        msg = input_msg_array.pop()
        msg_payload = msg[20:]
        
        msg_type = bytes.decode(msg[:12].strip(b"\x00"))
        print(f"New message: {msg_type}")
        
        if msg_type == "inv":
            invs = parse_invs(msg_payload)
            getdata_payload = create_getdata(invs)
            getdata = MAGIC_NUMBER + create_header(getdata_payload, "getdata") + getdata_payload
            sock.send(getdata)
            continue
        
        if msg_type == "ping":
            pong = MAGIC_NUMBER + create_header(msg_payload, "pong") + msg_payload
            sock.send(pong)
            continue
        
        if msg_type == "version":
            print(parse_version(msg_payload))
            
            # VERACK & FEEFILTER
            sock.send(HARDCODED_PACKETS["VERACK"])
            sock.send(HARDCODED_PACKETS["FEEFILTER"])
            continue
        
sock.close()
wlan.disconnect()
