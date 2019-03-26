from collections import defaultdict
import logging
import random

from scapy.all import *

import fuzzer.TCPSession as ts
import fuzzer.utils as utils

class TCPFuzzer:

    def __init__(self, src, dst, mode, payload, fields):
        self.shost, self.sport = src
        self.dhost, self.dport = dst
        
        self.payload = payload
        self.fields = set(fields)

        self.tcp = { # range of values of each field
            'seq': 1 << 32, 'ack': 1 << 32, 'dataofs': 1 << 4, 'reserved': 1 << 3,
            'flags': 1 << 9, 'window': 1 << 16, 'urgptr': 1 << 16
        }
    
    def run_default(self, max_tests):
        logging.info("Running default tests on TCP layer...")
        sess = ts.TCPSession(self.shost, self.dhost, self.sport, self.dport, timeout=0.1)
        
        if sess.connect():
            # sess.send(IP()/TCP()/Raw(load=self.payload))
            tests = defaultdict(list)
            
            # For fields with few bits, try every possible value
            # for version in range(self.ipv4['version']):
            #     tests['version'].append(IP(version=version))
            # for ihl in range(self.ipv4['ihl']):
            #     tests['ihl'].append(IP(ihl=ihl))
            # for tos in range(self.ipv4['tos']):
            #     tests['tos'].append(IP(tos=tos))
            # for flags in range(self.ipv4['flags']):
            #     tests['flags'].append(IP(flags=flags))
            # for ttl in range(self.ipv4['ttl']):
            #     tests['ttl'].append(IP(ttl=ttl))
            # for proto in range(self.ipv4['proto']):
            #     tests['proto'].append(IP(proto=proto))
            
            # For other fields, try max_tests random values
            # len_samples = random.sample(range(self.ipv4['len']), self.max_tests)
            # for len_sample in len_samples:
            #     tests['len'].append(IP(len=len_sample))
            # id_samples = random.sample(range(self.ipv4['id']), self.max_tests)
            # for id_sample in id_samples:
            #     tests['id'].append(IP(id=id_sample))
            # frag_samples = random.sample(range(self.ipv4['frag']), self.max_tests)
            # for frag_sample in frag_samples:
            #     tests['frag'].append(IP(id=frag_sample))
# 
            # for field, test in tests.items():
            #     if 'all' in self.fields or field in self.fields: # only test user-specified fields
            #         for packet in test:
            #             sess.send(packet/TCP()/Raw(load=self.payload))

            sess.close()

    def run_custom(self, test_file, max_tests):
        logging.info("Running custom tests on TCP layer...")

        # Read the tests
        treader = utils.TestFileReader(test_file)
        tests = treader.read_tests(max_tests)

        sess = ts.TCPSession(self.shost, self.dhost, self.sport, self.dport, timeout=0.1)

        if sess.connect():
            for tid, test in tests:
                packet = TCP()
                for field, value in test:
                    if field == 'seq':
                        packet.seq = value
                    elif field == 'ack':
                        packet.ack = value
                    elif field == 'dataofs':
                        packet.dataofs = value
                    elif field == 'reserved':
                        packet.reserved = value
                    elif field == 'tcp_flags':
                        packet.flags = value
                    elif field == 'window':
                        packet.window = value
                    elif field == 'urgptr':
                        packet.urgptr = value
                    else:
                        print('Unknown field ' + field + 'in test ' + tid + '. Skipping...')
                sess.send(packet/TCP()/Raw(load=self.payload))
            
            sess.close()
