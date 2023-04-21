# WIFI CREDENTIALS
SSID= ''
PASSWORD= ''

# BITCOIN MAGIC NUMBER
MAGIC_NUMBER = const(b'\xf9\xbe\xb4\xd9')

# KNOWN IP ADDRESSES FROM SIPA'S PUBLIC DNS SERVER (seed.bitcoin.sipa.be)
KNOWN_NODES = [
        '168.119.86.21',  '24.222.43.8',    '24.56.46.227',   '95.89.57.66',    '88.198.57.103',
        '123.60.213.192', '136.32.238.6',   '51.148.160.195', '173.12.119.133', '91.215.91.254',
        '176.118.220.29', '81.205.54.6',    '108.26.125.214', '35.228.173.101', '107.141.227.162',
        '75.83.203.225',  '121.241.23.252', '78.98.117.139',  '51.222.152.48',  '78.153.235.174',
        '34.87.160.111',  '188.24.51.41',   '46.249.191.157', '213.168.190.59', '3.8.165.235'
    ]

HARDCODED_PACKETS = {
        "VERACK": b'\xf9\xbe\xb4\xd9verack\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00]\xf6\xe0\xe2',
        "FEEFILTER": b'\xf9\xbe\xb4\xd9feefilter\x00\x00\x00\x08\x00\x00\x00\xe8\x0f\xd1\x9f\xe8\x03\x00\x00\x00\x00\x00\x00',        
    }