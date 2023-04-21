from secrets import SSID, PASSWORD, KNOWN_NODES, MAGIC_NUMBER, HARDCODED_PACKETS
from socket import AF_INET, SOCK_STREAM, socket, getaddrinfo
from binascii import unhexlify, hexlify
from time import sleep, localtime
from network import WLAN, STA_IF
from random import choice
from machine import Pin
import gc

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
    
gc.enable()

print(f"WiFi status: {wlan.isconnected()}")

hostport = (choice(KNOWN_NODES), 8333)
print(f"Connecting to {hostport}")

sock = socket(AF_INET, SOCK_STREAM)
sock.settimeout(60)
sock.connect(hostport)

# VERSION MESSAGE
version_payload = create_version(70015, hostport, "/picotoshi:0.1/")
version_header = create_header(version_payload, "version")
version = MAGIC_NUMBER + version_header + version_payload
sock.send(version)

input_msg_array = []
inv_buffer = []
packet_buffer = b''

while wlan.isconnected():
    packet_received = sock.recv(1024)
    packet_buffer += packet_received
    buffer_pointer = packet_buffer.rfind(MAGIC_NUMBER)
    
    if buffer_pointer <= 0:
        continue
    
    complete_packets = packet_buffer[:buffer_pointer]
    packet_buffer = packet_buffer[buffer_pointer:]
            
    for msg in complete_packets.split(MAGIC_NUMBER):
        if len(msg) > 0 and is_header_valid(msg):
            input_msg_array.append(msg)
    
    while len(input_msg_array) > 0:
        msg = input_msg_array.pop()
        msg_payload = msg[20:]
        
        msg_type = bytes.decode(msg[:12].strip(b"\x00"))
        print(f"New message: {msg_type} (buffer size: {len(packet_buffer)})")
        
        if msg_type == "inv":
            inv_buffer = parse_invs(msg_payload)
            continue
        
        elif msg_type == "ping":
            pong = MAGIC_NUMBER + create_header(msg_payload, "pong") + msg_payload
            pong = b""
            sock.send(pong)
            continue
        
        elif msg_type == "version":
            node_version = parse_version(msg_payload)
            print(node_version)
            
            # VERACK & FEEFILTER
            sock.send(HARDCODED_PACKETS["VERACK"])
            sock.send(HARDCODED_PACKETS["FEEFILTER"])
            continue
        

    if len(inv_buffer) > 0:
        led.on()
        
        inv = inv_buffer.pop()
        getdata_payload = create_getdata(inv)
        getdata = MAGIC_NUMBER + create_header(getdata_payload, "getdata") + getdata_payload
        sock.send(getdata)
        
        # GARBAGE COLLECTOR
        gc.collect()
        
        led.off()
        continue
        
sock.close()
wlan.disconnect()
