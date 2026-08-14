import fcntl
import struct
import os
import threading
from constants import *
import subprocess
from colorama import Fore, Back, Style

import psutil
from scapy.layers.inet import TCP
from scapy.layers.inet import IP
from rpyutils import check_root, clear_ip_tables, set_ip_address


class TunInterface(threading.Thread):
    send_callback = None
    name = None
    virtual_ip = None

    def __init__(self, send_callback, virtual_ip, name="fakeap", enable_dns=False):
        threading.Thread.__init__(self)
        check_root()

        if len(name) > IFNAMSIZ:
            raise Exception("Tun interface name cannot be larger than " + str(IFNAMSIZ))

        self.send_callback = send_callback
        self.name = name
        self.virtual_ip = virtual_ip
        self.setDaemon(True)

        # Virtual interface
        self.fd = open('/dev/net/tun', 'r+b')
        ifr_flags = IFF_TUN | IFF_NO_PI  # Tun device without packet information
        ifreq = struct.pack('16sH', str(name), ifr_flags)
        fcntl.ioctl(self.fd, TUNSETIFF, ifreq)  # Syscall to create interface

        # Assign IP and bring interface up
        set_ip_address(name, self.virtual_ip + '/24')

        print(
                Fore.CYAN + "Created TUN interface " + Fore.LIGHTBLUE_EX + name + " at " + self.virtual_ip + ". " +
                Fore.CYAN + "Bind it to your services if needed.")

        if enable_dns:
            for inet_ps in psutil.net_connections(kind='inet'):
                # Find if there's running dnmasq on interface and kill its process
                if inet_ps.status is 'LISTEN' and inet_ps.laddr.port is 53 and inet_ps.laddr.ip in self.virtual_ip:
                    os.system('kill ' + str(inet_ps.pid))

            ip_array = self.virtual_ip.split('.')
            ip_array[3] = str(int(ip_array[3]) + 1)
            dnsmasq_ip_start = ".".join(ip_array)
            ip_array[3] = str(10)  # Range normally from *.2 to *.10, so 9 clients maximum
            dnsmasq_ip_end = ".".join(ip_array)
            s = "dnsmasq --interface=" + self.name + \
                " --except-interface=lo --bind-interfaces --dhcp-range=" + dnsmasq_ip_start + \
                "," + dnsmasq_ip_end + ",12h --conf-file=/dev/null"
            print(s)
            os.system(s)
            print(Fore.CYAN + 'DNS server started on ' + Fore.YELLOW + self.virtual_ip)

    def write(self, pkt):
        os.write(self.fd.fileno(), str(pkt[IP]))  # Strip layer 2

    def read(self):
        raw_packet = os.read(self.fd.fileno(), DOT11_MTU)
        return raw_packet

    def close(self):
        os.close(self.fd.fileno())

    def run(self):
        while True:
            ip_packet = IP(self.read())
            self.send_callback(ip_packet)
        print(Fore.RED + 'Virtual interface stopped')

    def share_internet(self, dev):
        TCP.payload_guess = []
        clear_ip_tables()

        # Postrouting
        if subprocess.call(
                ['iptables', '--table', 'nat', '--append', 'POSTROUTING', '--out-interface', dev, '-j', 'MASQUERADE']):
            print("Failed to setup postrouting for interface %s." % dev)

        # Forward
        if subprocess.call(['iptables', '--append', 'FORWARD', '--in-interface', self.name, '-j', 'ACCEPT']):
            print("Failed to setup forwarding for interface %s." % self.name)

        # Enable IP forwarding
        if "SUDO_GID" not in os.environ and subprocess.call(['sysctl', '-w', 'net.ipv4.ip_forward=1']):
            print("Failed to enable IP forwarding.")

        print(Fore.CYAN + "IP packets will be routed through " + Fore.YELLOW + dev)
