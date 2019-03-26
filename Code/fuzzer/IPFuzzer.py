from collections import defaultdict
import logging
import random

from scapy.all import *

import fuzzer.TCPSession as ts
import fuzzer.utils as utils

class IPFuzzer:

    def __init__(self, src, dst, payload, fields):
        self.shost, self.sport = src
        self.dhost, self.dport = dst
        
        self.payload = payload
        self.fields = set(fields)

        self.ipv4 = { # range of values of each field
            'version': 1 << 4, 'ihl': 1 << 4, 'tos': 1 << 8, 'len': 1 << 16,
            'id': 1 << 16, 'flags': 1 << 3, 'frag': 1 << 13, 'ttl': 1 << 8, 'proto': 1 << 8
        }
    
    def run_default(self, max_tests):
        logging.info("Running default tests on IP layer...")
        sess = ts.TCPSession(self.shost, self.dhost, self.sport, self.dport, timeout=0.1)
        
        if sess.connect():
            # sess.send(IP()/TCP()/Raw(load=self.payload))
            tests = defaultdict(list)
            
            # For fields with few bits, try every possible value
            for version in range(self.ipv4['version']):
                tests['version'].append(IP(version=version))
            for ihl in range(self.ipv4['ihl']):
                tests['ihl'].append(IP(ihl=ihl))
            for tos in range(self.ipv4['tos']):
                tests['tos'].append(IP(tos=tos))
            for flags in range(self.ipv4['flags']):
                tests['flags'].append(IP(flags=flags))
            for ttl in range(self.ipv4['ttl']):
                tests['ttl'].append(IP(ttl=ttl))
            for proto in range(self.ipv4['proto']):
                tests['proto'].append(IP(proto=proto))
            
            # For other fields, try max_tests random values
            len_samples = random.sample(range(self.ipv4['len']), max_tests)
            for len_sample in len_samples:
                tests['len'].append(IP(len=len_sample))
            id_samples = random.sample(range(self.ipv4['id']), max_tests)
            for id_sample in id_samples:
                tests['id'].append(IP(id=id_sample))
            frag_samples = random.sample(range(self.ipv4['frag']), max_tests)
            for frag_sample in frag_samples:
                tests['frag'].append(IP(id=frag_sample))

            for field, test in tests.items():
                if 'all' in self.fields or field in self.fields: # only test user-specified fields
                    for packet in test:
                        sess.send(packet/TCP()/Raw(load=self.payload))

            sess.close()

    def run_custom(self, test_file, max_tests):
        logging.info("Running custom tests on IP layer...")

        # Read the tests
        treader = utils.TestFileReader(test_file)
        tests = treader.read_tests(max_tests)

        sess = ts.TCPSession(self.shost, self.dhost, self.sport, self.dport, timeout=0.1)

        if sess.connect():
            for tid, test in tests:
                packet = IP()
                for field, value in test:
                    if field == 'version':
                        packet.version = value
                    elif field == 'ihl':
                        packet.ihl = value
                    elif field == 'tos':
                        packet.tos = value
                    elif field == 'len':
                        packet.len = value
                    elif field == 'id':
                        packet.id = value
                    elif field == 'ip_flags':
                        packet.flags = value
                    elif field == 'frag':
                        packet.frag = value
                    elif field == 'ttl':
                        packet.ttl = value
                    elif field == 'proto':
                        packet.field = value
                    else:
                        print('Unknown field ' + field + 'in test ' + tid + '. Skipping...')
                sess.send(packet/TCP()/Raw(load=self.payload))

            sess.close()
