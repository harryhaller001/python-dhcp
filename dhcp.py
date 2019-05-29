"""
Based on "dhcp query" from http://code.activestate.com/recipes/577649-dhcp-query/ (MIT License)

"""
import socket
import struct
from uuid import getnode as get_mac
from random import randint

# DHCP Option list (official RFC references, unused defined under RFC 3679)
DHCP_OPTIONS = {
    1: "subnet-mask",
    2: "time-offset",
    3: "router",
    4: "time-server",
    5: "name-server",
    6: "domain-name-server",
    7: "log-server",
    8: "quote-server",
    9: "lpr-server",
    10: "impress-server",
    11: "resource-location-server",
    12: "host-name",
    13: "boot-file-size",
    14: "merit-dump-file",
    15: "domain-name",
    16: "swap-server",
    17: "root-path",
    18: "extensions-path",
    19: "ip-forwarding",
    20: "non-local-source-routing",
    21: "policy-filter",
    22: "max-datagram-size",
    23: "time-to-live",
    24: "path-mtu-aging-timeout",
    25: "path-mtu-plateau-table",
    26: "interface-mtu",
    27: "all-subnets-are-local",
    28: "broadcast-address",
    29: "perform-router-discovery",
    30: "mask-supplier",
    31: "perform-router-discovery",
    32: "router-solicitation-address",
    33: "static-routing-table",
    34: "trailer-encapsulation",
    35: "arp-cache-timeout",
    36: "ethernet-encapsulation",
    37: "default-tcp-ttl",
    38: "tcp-keepalive-interval",
    39: "tcp-keepalive-garbage",
    40: "network-information-service-domain",
    41: "network-information-servers",
    42: "ntp-servers",
    43: "vendor-specific-information",
    44: "netbios-over-tcp-name-server",
    45: "netbios-over-tcp-datagram-distribution-server",
    46: "netbios-over-tcp-node-type",
    47: "netbios-over-tcp-scope",
    48: "x-windows-system-font-server",
    49: "x-windows-system-display-manager",
    50: "requested-ip-address",
    51: "ip-addr-lease-time",
    52: "option-overload",
    53: "dhcp-message-type",
    54: "server-identifier",
    55: "parameter-request-list",
    56: "message",
    57: "max-dhcp-message-size",
    58: "renew-time-value",
    59: "rebinding-time-value",
    60: "class-identifier",
    61: "client-identifier",
    62: "netware-domain-name",
    63: "netware-information",
    64: "network-information-service+-domain",
    65: "network-information-service+servers",
    66: "tftp-server-name",
    67: "bootfile-name",
    68: "mobile-ip-home-agent",
    69: "smtp-server",
    70: "post-office-protocol-server",
    71: "network-news-transport-protocol-server",
    72: "default-www-server",
    73: "default-finger-server",
    74: "default-internet-relay-chat-server",
    75: "streettalk-server",
    76: "streettalk-directory-assistence-server",
    77: "user-class-information",
    78: "slp-directory-agent",
    79: "slp-service-scope",
    80: "rapid-commit",
    81: "fqdn",
    82: "relay-agent-information",
    83: "internet-storage-name-service",
    85: "nds-servers",
    86: "nds-tree-name",
    87: "nds-context",
    88: "bcmcs-controller-domain-name-list",
    89: "bcmcs-controller-ipv4-address-list",
    90: "authentication",
    91: "client-last-transaction-time",
    92: "associated-ip",
    93: "client-system-architecture-type",
    94: "client-network-interface-identifier",
    95: "ldap",
    97: "client-machine-identifier",
    98: "open-groups-user-auth",
    99: "geoconf-civic",
    100: "ieee-1003-1-tz-string",
    101: "reference-to-the-tz-datbase",
    112: "netinfo-parent-server-address",
    113: "netinfo-parent-server-tag",
    114: "url",
    116: "auto-configure",
    117: "name-service-search",
    118: "subnet-selection",
    119: "dns-domain-search-list",
    120: "sip-servers-dhcp-option",
    121: "clasless-static-route-option",
    122: "cablelabs-client-configuration",
    123: "geoconf",
    124: "vendor-identifying-vendor-class",
    125: "vendor-identifying-vendor-specific",
    128: "tftp-server-ip-address",
    129: "call-server-ip-address",
    130: "discrimination-string",
    131: "remote-statistics-server-ip-address",
    132: "802-1-vlan-id",
    133: "802-1-l2-priority",
    134: "diffserv-code-point",
    135: "http-proxy-for-phone.specific-application",
    136: "pana-authentication-agent",
    137: "lost-server",
    138: "capwap-access-controller-addresses",
    139: "option-ipv4-address-mos",
    140: "option-ipv6-fqdn-mos",
    141: "sip-ua-configuration-service-domains",
    142: "option-ipv4-address-andsf",
    143: "option-ipv6-address-andsf",
    150: "tftp-server-address",
    208: "pxelinux-magic-string",
    209: "pxelinux-configfile",
    210: "prelinux-pathprefix",
    211: "pxelinux-reboottime",
    212: "option-6rd",
    213: "option-v4-access-domain",
    221: "subnet-allocation",
    255: "end"
}


MAGIC_COOKIE = b"\x63\x82\x53\x63"


def get_mac_as_bytes():
    mac = str(hex(get_mac()))
    mac = mac[2:]
    while len(mac) < 12:
        mac = '0' + mac
    macb = b''
    for i in range(0, 12, 2):
        m = int(mac[i:i + 2], 16)
        macb += struct.pack('!B', m)
    return macb


def get_transaction_id():
    transaction = b''
    for i in range(4):
        transaction += struct.pack('!B', randint(0, 255))
    return transaction


def build_packet(transaction_id):
    macb = get_mac_as_bytes()
    packet = b''
    packet += b'\x01'  # Message type: Boot Request (1)
    packet += b'\x01'  # Hardware type: Ethernet
    packet += b'\x06'  # Hardware address length: 6
    packet += b'\x00'  # Hops: 0
    packet += transaction_id  # Transaction ID
    packet += b'\x00\x00'  # Seconds elapsed: 0
    packet += b'\x80\x00'  # Bootp flags: 0x8000 (Broadcast) + reserved flags
    packet += b'\x00\x00\x00\x00'  # Client IP address: 0.0.0.0
    packet += b'\x00\x00\x00\x00'  # Your (client) IP address: 0.0.0.0
    packet += b'\x00\x00\x00\x00'  # Next server IP address: 0.0.0.0
    packet += b'\x00\x00\x00\x00'  # Relay agent IP address: 0.0.0.0
    # packet += b'\x00\x26\x9e\x04\x1e\x9b'   #Client MAC address: 00:26:9e:04:1e:9b
    packet += macb
    packet += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'  # Client hardware address padding: 00000000000000000000
    packet += b'\x00' * 67  # Server host name not given
    packet += b'\x00' * 125  # Boot file name not given
    packet += b'\x63\x82\x53\x63'  # Magic cookie: DHCP
    packet += b'\x35\x01\x01'  # Option: (t=53,l=1) DHCP Message Type = DHCP Discover
    # packet += b'\x3d\x06\x00\x26\x9e\x04\x1e\x9b'   #Option: (t=61,l=6) Client identifier
    packet += b'\x3d\x06' + macb
    packet += b'\x37\x03\x03\x01\x06'  # Option: (t=55,l=3) Parameter Request List
    packet += b'\xff'  # End Option
    return packet


def unpack_ip(i):
    return ".".join(list(map(lambda x: str(int(x)), i)))


def unpack_mac(i):
    return ":".join(list(map(lambda x: hex(int(x))[2:], i)))


def parse_options(of):
    if not of[:4] == MAGIC_COOKIE:
        raise ValueError("DHCP response have no magic cookie")

    parsed = {}
    cnt = 4

    while True:
        option = of[cnt]
        if option == 255:
            break
        offset = of[cnt + 1]
        dat = of[cnt + 2:cnt + 2 + offset]
        parsed[DHCP_OPTIONS.get(option, option)] = dat
        cnt += 2 + len(dat)

    return parsed


def unpack(data):
    return {"op": data[0], "htype": data[1],
                  "hlen": data[2], "hops": data[3],
                  "id": data[4:8],
                  "client-addr": unpack_ip(data[12:16]),
                  "your-addr": unpack_ip(data[16:20]),
                  "server-addr": unpack_ip(data[20:24]),
                  "relay-addr": unpack_ip(data[24:28]),
                  "client-mac": unpack_mac(data[28:34]),
                  "server-name": data[44:108],
                  "file": data[108:236],
                  "options": parse_options(data[236:])
            }


def get_subnet_mask():
    return request().get("subnet-mask", None)


def request():
    result = full_request()
    return {"client-addr": result["your-addr"],
            "server-addr": result["server-addr"],
            "subnet-mask": unpack_ip(result["options"].get("subnet-mask", b"\xff\xff\xff\x00"))}


def full_request():
    dhcps = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    dhcps.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    try:
        dhcps.bind(('', 68))
    except Exception as e:
        dhcps.close()
        return None

    transaction_id = get_transaction_id()
    dhcps.sendto(build_packet(transaction_id=transaction_id), ('<broadcast>', 67))
    dhcps.settimeout(3)

    try:
        data = dhcps.recv(1024)
        result = unpack(data)
        dhcps.close()

        if not result["id"] == transaction_id:
            raise ValueError("Transaction ID is not fitting!")

        return result

    except socket.timeout:
        dhcps.close()
        return None


if __name__ == '__main__':

    res = request()

    if res:
        print("IP-Address: %s" % res["client-addr"])
        print("Server-Address: %s" % res["server-addr"])
        print("Subnet-Mask: %s" % res["subnet-mask"])



