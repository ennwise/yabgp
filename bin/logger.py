#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import print_function
import sys
import os
import json
import ipaddress
import threading
import queue
from flask import Flask, request, jsonify

possible_topdir = os.path.normpath(os.path.join(os.path.abspath(__file__),
                                                os.pardir,
                                                os.pardir))

if os.path.exists(os.path.join(possible_topdir,
                               'yabgp',
                               '__init__.py')):
    # use the module in current work dir if applicable
    sys.path.insert(0, possible_topdir)
else:
    # seems has no effect
    # possible_topdir = '/'
    pass

from yabgp.agent import prepare_service
from yabgp.handler import BaseHandler

class TrieNode:
    def __init__(self):
        self.children = {}
        self.asn = None

class IPv4PrefixTrie:
    def __init__(self):
        self.root = TrieNode()

    def insert(self, prefix, asn):
        node = self.root
        for bit in self._prefix_to_bits(prefix):
            if bit not in node.children:
                node.children[bit] = TrieNode()
            node = node.children[bit]
        node.asn = asn

    def remove(self, prefix):
        def _remove(node, bits, depth):
            if depth == len(bits):
                node.asn = None
                return len(node.children) == 0
            bit = bits[depth]
            if bit in node.children and _remove(node.children[bit], bits, depth + 1):
                del node.children[bit]
                return len(node.children) == 0 and node.asn is None
            return False

        _remove(self.root, self._prefix_to_bits(prefix), 0)

    def lookup(self, ip):
        node = self.root
        last_asn = None
        for bit in self._ip_to_bits(ip):
            if node.asn is not None:
                last_asn = node.asn
            if bit in node.children:
                node = node.children[bit]
            else:
                break
        return last_asn

    def _prefix_to_bits(self, prefix):
        ip, length = prefix.split('/')
        length = int(length)
        bits = self._ip_to_bits(ip)
        return bits[:length]

    def _ip_to_bits(self, ip):
        return ''.join(f'{int(octet):08b}' for octet in ip.split('.'))

class IPv6PrefixTrie:
    def __init__(self):
        self.root = TrieNode()

    def insert(self, prefix, asn):
        node = self.root
        for bit in self._prefix_to_bits(prefix):
            if bit not in node.children:
                node.children[bit] = TrieNode()
            node = node.children[bit]
        node.asn = asn

    def remove(self, prefix):
        def _remove(node, bits, depth):
            if depth == len(bits):
                node.asn = None
                return len(node.children) == 0
            bit = bits[depth]
            if bit in node.children and _remove(node.children[bit], bits, depth + 1):
                del node.children[bit]
                return len(node.children) == 0 and node.asn is None
            return False

        _remove(self.root, self._prefix_to_bits(prefix), 0)

    def lookup(self, ip):
        node = self.root
        last_asn = None
        for bit in self._ip_to_bits(ip):
            if node.asn is not None:
                last_asn = node.asn
            if bit in node.children:
                node = node.children[bit]
            else:
                break
        return last_asn

    def _prefix_to_bits(self, prefix):
        ip, length = prefix.split('/')
        length = int(length)
        bits = self._ip_to_bits(ip)
        return bits[:length]

    def _ip_to_bits(self, ip):
        expanded_ip = ipaddress.ip_address(ip).exploded
        return ''.join(f'{int(part, 16):016b}' for part in expanded_ip.split(':'))


# define an enum 0 ipv4, 1 ipv6
class IPVersion:
    IPv4 = 0
    IPv6 = 1

class LoggerHandler(BaseHandler):
    def __init__(self):
        super(LoggerHandler, self).__init__()   
        self.ipv4_trie = IPv4PrefixTrie()
        self.ipv6_trie = IPv6PrefixTrie()
        self.message_queue = queue.Queue()
        self.worker_thread = threading.Thread(target=self.process_messages)
        self.worker_thread.daemon = True
        self.worker_thread.start()
        self.ipv4_lock = threading.Lock()
        self.ipv6_lock = threading.Lock()

    def init(self):
        return

    def on_update_error(self, peer, timestamp, msg):
        print('[-] UPDATE ERROR,', msg)

    def process_messages(self):
        while True:
            peer, timestamp, msg = self.message_queue.get()
            self.handle_update(peer, timestamp, msg)
            self.message_queue.task_done()

    def update_received(self, peer, timestamp, msg):
        self.message_queue.put((peer, timestamp, msg))
    
    def handle_update(self, peer, timestamp, msg):

        active_prefixes = []
        withdraw_prefixes = []
        as_path = None
        originating_asn = None

        if 'attr' in msg:
            if 2 in msg['attr']:
                as_path = msg['attr'][2]
                if as_path and isinstance(as_path, list):
                    # Iterate through the AS path to find the originating ASN
                    for segment in as_path:
                        if isinstance(segment, tuple) and len(segment) == 2 and isinstance(segment[1], list):
                            originating_asn = segment[1][-1]  # Get the last ASN in the segment

            if 14 in msg['attr']:
                attr_14 = msg['attr'][14]
                if 'nlri' in attr_14:
                    for prefix in attr_14['nlri']:
                        # ensute prefix isn't 0.0.0/0'
                        if prefix != '0.0.0.0/0':
                            active_prefixes.append((IPVersion.IPv6, prefix, originating_asn))
            if 15 in msg['attr']:
                attr_15 = msg['attr'][15]
                if 'withdraw' in attr_15:
                    for prefix in attr_15['withdraw']:
                        withdraw_prefixes.append((IPVersion.IPv6, prefix, None))

    
        if msg['nlri']:
            for prefix in msg['nlri']:
                active_prefixes.append((IPVersion.IPv4, prefix, originating_asn))
        if msg['withdraw']:
            for prefix in msg['withdraw']:
                withdraw_prefixes.append((IPVersion.IPv4, prefix, None))

        if ( originating_asn == None and active_prefixes ) and len(msg['attr'][2]) > 0:
            print('[-] No originating ASN', msg)
            return
        
        if not active_prefixes and not withdraw_prefixes:
            print('[-] No prefixes', msg)

        # Lock the appropriate trie and add or remove prefixes
        ipv4_active_prefixes = [prefix for ip_version, prefix, asn in active_prefixes if ip_version == IPVersion.IPv4]
        ipv4_withdraw_prefixes = [prefix for ip_version, prefix, _ in withdraw_prefixes if ip_version == IPVersion.IPv4]
        ipv6_active_prefixes = [prefix for ip_version, prefix, asn in active_prefixes if ip_version == IPVersion.IPv6]
        ipv6_withdraw_prefixes = [prefix for ip_version, prefix, _ in withdraw_prefixes if ip_version == IPVersion.IPv6]

        with self.ipv4_lock:
            for prefix in ipv4_active_prefixes:
                self.ipv4_trie.insert(prefix, originating_asn)
            for prefix in ipv4_withdraw_prefixes:
                self.ipv4_trie.remove(prefix)

        with self.ipv6_lock:
            for prefix in ipv6_active_prefixes:
                self.ipv6_trie.insert(prefix, originating_asn)
            for prefix in ipv6_withdraw_prefixes:
                self.ipv6_trie.remove(prefix)
       
        

   
    def keepalive_received(self, peer, timestamp):
        print('[+] KEEPALIVE received')

    def send_open(self, peer, timestamp, msg):
        print('[+] OPEN sent,', msg)

    def open_received(self, peer, timestamp, result):
        print('[+] OPEN received,', result)

    def route_refresh_received(self, peer, msg, msg_type):
        print('[+] ROUTE_REFRESH received,', msg)

    def notification_received(self, peer, msg):
        print('[-] NOTIFICATION received,', msg)

    def on_connection_lost(self, peer):
        print('[-] CONNECTION lost')

    def on_connection_failed(self, peer, msg):
        print('[-] CONNECTION failed,', msg)

    def on_established(self, peer, msg):
        pass
def main():
    try:
        cli_handler = LoggerHandler()
        prepare_service(handler=cli_handler)
    except Exception as e:
        print(e)

app = Flask(__name__)
logger_handler = LoggerHandler()

@app.route('/lookup', methods=['GET'])
def lookup():
    prefix = request.args.get('prefix')
    if not prefix:
        return jsonify({'error': 'Prefix is required'}), 400

    ip_version = IPVersion.IPv4 if '.' in prefix else IPVersion.IPv6
    if ip_version == IPVersion.IPv4:
        with logger_handler.ipv4_lock:
            asn = logger_handler.ipv4_trie.lookup(prefix.split('/')[0])
    else:
        with logger_handler.ipv6_lock:
            asn = logger_handler.ipv6_trie.lookup(prefix.split('/')[0])

    if asn is None:
        return jsonify({'error': 'ASN not found'}), 404

    return jsonify({'asn': asn})


def run_flask_app():
    app.run(host='0.0.0.0', port=5000)

def main():
    try:
        flask_thread = threading.Thread(target=run_flask_app)
        flask_thread.daemon = True
        flask_thread.start()
        cli_handler = logger_handler
        prepare_service(handler=cli_handler)
    except Exception as e:
        print(e)

if __name__ == '__main__':
    sys.exit(main())




