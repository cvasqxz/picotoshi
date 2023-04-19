from hashlib import sha256
from struct import pack, unpack
from time import time

SERVICES = {
    "NODE_NETWORK": (1 << 0),
    "NODE_BLOOM": (1 << 2),
    "NODE_WITNESS": (1 << 3),
    "NODE_COMPACT_FILTERS": (1 << 6),
    "NODE_NETWORK_LIMITED": (1 << 10),
}


def create_header(msg, msg_type):
    type_msg = msg_type.encode() + b'\x00'*(12 - len(msg_type))
    length_msg = (len(msg)).to_bytes(4, "little")
    checksum = double256(msg)[:4]

    return type_msg + length_msg + checksum


def is_header_valid(s):
    length = int.from_bytes(s[12:16], "little")
    checksum = s[16:20]

    is_length = length == len(s[20:])
    is_checksum = checksum == double256(s[20:])[:4]

    return is_length and is_checksum


def create_version(int_version, host_port, agent):

    selected_services = SERVICES["NODE_NETWORK"]
    selected_services |= SERVICES["NODE_WITNESS"]
    selected_services |= SERVICES["NODE_NETWORK_LIMITED"]

    host, port = host_port

    VERSION = pack("<L", int_version)
    SERVICE = pack("<Q", selected_services)
    EPOCH = pack("<Q", int(time()))
    RECV_ADDR = ip2b(host)
    RECV_PORT = pack(">H", port)
    NODE_ADDR = b'\x00'*16
    NODE_PORT = b'\x00'*2
    NONCE = b'\x00'*8
    LENGTH_USERAGENT = pack("<B", 1)
    USERAGENT = agent.encode()
    START_HEIGHT = b'\x01\x00\x00\x00'

    RELAY = b"\x01"

    return (
        VERSION
        + SERVICE
        + EPOCH
        + SERVICE
        + RECV_ADDR
        + RECV_PORT
        + SERVICE
        + NODE_ADDR
        + NODE_PORT
        + NONCE
        + LENGTH_USERAGENT
        + USERAGENT
        + START_HEIGHT
        + RELAY
    )


def parse_version(s):
    version = int.from_bytes(s[0:4], "little")
    services = int.from_bytes(s[4:12], "little")

    node_services = []

    for tag in SERVICES:
        if (SERVICES[tag] & services) > 0:
            node_services.append(tag)

    len_agent = s[80]
    agent = bytes.decode(s[81 : 81 + len_agent])

    return agent, ", ".join(node_services), version


def ip2b(s):
    ip_s = s.split(".")
    ip_i = 0
    
    for i in range(len(ip_s)):
        ip_i += int(ip_s[i]) * 2 ** (24 - 8 * i)
        
    ip_i = 0xFFFF00000000 + ip_i
    
    return b'\x00'*8 + pack(">Q", ip_i)


def double256(s):
    return sha256(sha256(s).digest()).digest()


def parse_varint(s):
    if s[0] < 0xFD:
        return s[0], 1
    if s[0] == 0xFD:
        return unpack("<H", s[1:3])[0], 3
    if s[0] == 0xFE:
        return unpack("<I", s[1:5])[0], 5
    if s[0] == 0xFF:
        return unpack("<Q", s[1:9])[0], 9


def create_varint(i):
    if i < 0xFD:
        return pack("<B", i)
    if i >= 0xFD and i <= 0xFFFF:
        return b"\xFD" + pack("<H", i)
    if i > 0xFFFF and i <= 0xFFFFFFFF:
        return b"\xFE" + pack("<I", i)
    if i > 0xFFFFFFFF:
        return b"\xFF" + pack("<Q", i)


inv_types = {
    0x01: "MSG_TX",
    0x02: "MSG_BLOCK",
    0x03: "MSG_FILTERED_BLOCK",
    0x04: "MSG_CMPCT_BLOCK",
}

# https://www.geeksforgeeks.org/python-program-to-swap-keys-and-values-in-dictionary/
reversed_inv_types = dict([(value, key) for key, value in inv_types.items()])


def reverse_bytearray(s):
    output = ""
    
    for n in range(len(s)):
        output = chr(s[n]) + output
        
    return output.encode()


def parse_invs(s):
    length_inv, bytes_read = parse_varint(s)
    inv_array = []

    for i in range(length_inv):
        inv = s[bytes_read + 36 * i : bytes_read + 36 * (i + 1)]
        inv_type = unpack("<L", inv[0:4])[0]
        inv_type = inv_types[inv_type]

        inv_content = reverse_bytearray(inv[4:])

        inv_array.append({"type": inv_type, "content": inv_content})

    return inv_array


def create_getdata(inv_array):
    # ESTO ESTA MAL, ES UN VARINT
    s = create_varint(len(inv_array))

    for inv in inv_array:
        inv_code = reversed_inv_types[inv["type"]]

        # https://github.com/bitcoin/bips/blob/master/bip-0144.mediawiki
        if inv["type"] in ["MSG_TX", "MSG_BLOCK"]:
            inv_code += 1 << 30

        s += pack("<L", inv_code)
        s += reverse_bytearray(inv["content"])

    return s
