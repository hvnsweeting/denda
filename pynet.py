#!/usr/bin/env python3
# -*- coding: utf-8 -*-

'''
Python network discover tool
'''


import json
import logging
import re
import sys
import subprocess as spr
import urllib.request
import sqlite3


import netifaces

conn = sqlite3.connect('data.db')

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

PERCENT = re.compile('\d+\.*\d*%')


def ping(ip):
    logger.info("Pinging %s", ip)
    cmd = ['ping', '-c3', ip]
    for line in cmdoutlines(cmd):
        if 'packet loss' in line:
            loss = PERCENT.findall(line)[0]
            continue
        if line.startswith('round-trip'):
            min_, avg, max_, stddev = line.split(
                ' = '
            )[1].strip(' ms').split('/')
            print(loss, avg)


class PyNet(object):
    def __init__(self):
        self.interface = None
        self.gateway = None
        self.lan_ipv4 = None

        self.load_interfaces()
        self.hosts = []

    def __str__(self):
        return "interface: {0} - IPv4: {1} - mask: {2}".format(
                self.interface,
                self.lan_ipv4,
                self.netmask
        )

    def load_interfaces(self):
        logger.info("Getting default interface")
        iface = netifaces.gateways()['default'][netifaces.AF_INET]
        self.gateway, self.interface = iface

        iface = netifaces.ifaddresses(self.interface)[netifaces.AF_INET][0]
        self.lan_ipv4 = iface['addr']
        self.broadcast = iface['broadcast']
        self.netmask = iface['netmask']

    def get_gateway(self):
        return self.gateway

    def get_router_mac(self):
        mac = self.get_mac(self.gateway)
        return mac

    def get_mac(self, lan_ipv4):
        cmd = ['arp', '-n', lan_ipv4]
        for line in cmdoutlines(cmd):
            if lan_ipv4 in line:
                # Tested on OSX
                return line.split('at')[1].split('on')[0].strip()

        assert False

    def scan_network(self):
        cidr = self.lan_ipv4 + "/" + get_net_size(self.netmask)
        logger.info("Nmap scanning CIDR: %s", cidr)
        cmd = ["nmap", "-sP", cidr]
        output = spr.check_output(cmd)
        for line in output.splitlines():
            logger.debug("Nmap output: %s", line)
            line = line.decode().split()
            if self.lan_ipv4 in line:
                continue
            # Nmap scan report for 10.235.51.221
            if "for" in line:
                self.hosts.append(line[-1])
        if len(self.hosts) == 1:
            sys.exit("Found only myself")

    def show_hosts(self):
        logger.info("Showing found hosts:")
        for host in self.hosts:
            print("FOUND %s" % host)

    @staticmethod
    def ping_sweep(ip):
        cmd = ["nmap", "-sn", ip]
        logger.info("nmap ping sweep: %s", cmd)
        for line in cmdoutlines(cmd):
            logger.debug(line)

    def get_ssid(self):
        cmd = ['/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport', 'en0', '-I'] # NOQA
        for output in cmdoutlines(cmd):
            if 'SSID:' in output:
                return output.split(':')[1].strip()

    def full_scan(self, ip):
        cmd = ["nmap", "-A", "-T4", ip]
        logger.info("nmap fullscan: %s", cmd)
        for line in cmdoutlines(cmd):
            logger.debug(line)

    def show_gateway(self):
        self.full_scan(self.gateway)

    def get_wan_ip(self):
        logger.info("Getting WAN data:")

        with urllib.request.urlopen(
            urllib.request.Request(
                'https://ipinfo.io',
                # fake as python-requests since the site does not support
                # default python user-agent
                headers={'User-Agent': 'python-requests/2.10.0'})
        ) as f:
            data = f.read()
            logger.debug("Got wan info: %s", data)
            try:
                self.wan = json.loads(data.decode())
            except json.decoder.JSONDecodeError:
                # TODO use dig when cannot get by ipinfo
                raise
        return self.wan['ip']


def get_net_size(netmask):
    binary_str = ''
    for octet in netmask.split('.'):
        binary_str += bin(int(octet))[2:].zfill(8)
    return str(len(binary_str.rstrip('0')))


def cmdoutlines(cmd):
    for line in spr.check_output(cmd).splitlines():
        yield line.decode().strip()


def create_db():
    c = conn.cursor()
    CREATE = '''CREATE TABLE IF NOT EXISTS nets
                (timestamp text default CURRENT_TIMESTAMP,
                 mac text UNIQUE,
                 ssid text,
                 wan_ip text,
                 isp text,
                 gw_host text,
                 gw_os text,
                 gw_ports text,
                 netspeed text)'''
    c.execute(CREATE)
    conn.commit()


def save_data(data):
    data = (data['mac'], data['ssid'], data['wan_ip'],
            data['isp'],
            data['gw_host'],
            data['gw_os'], data['gw_ports'], data['netspeed'], )
    query = '''INSERT INTO nets (mac, ssid, wan_ip, isp, gw_host, gw_os,
                gw_ports, netspeed)
            values (?, ?, ?, ?, ?, ?, ?, ?)'''

    c = conn.cursor()
    c.execute(query, data)
    conn.commit()


def main():
    # TODO ping 3 different sources
    create_db()
    c = PyNet()
    print(c)
    print(c.get_router_mac())
    data = {'mac': c.get_router_mac(),
            'ssid': c.get_ssid(),
            'wan_ip': c.get_wan_ip(),
            'gw_host': '',
            'gw_os': '',
            'gw_ports': 'TODO',
            'netspeed': 'TODO',
            'isp': c.wan['org'],
            }
    save_data(data)
    #c.scan_network()
    #c.show_hosts()
    #for host_ip in c.hosts:
    #    # PyNet.ping(host)
    #    # PyNet.ping_sweep(host)
    #    # c.full_scan(host)
    #    pass

    #c.show_gateway()

    # - save all data to db
    # tables
    # WanIP - LANIP, DefaultRroute,  ISP, hostname, location, timestamp, SSID
    # WanIP,LanIP foreign key - hosts
    # hosts table (MAP, ip, hostname, ping, port, device type, misc, time)

    # TODO get wifiname
    conn.close()


if __name__ == "__main__":
    main()
