from collections import defaultdict
import logging
import random

from scapy.all import *

import fuzzer.TCPSession as ts
import fuzzer.utils as utils

class TCPFuzzer:

    def __init__(self, src, dst, payload, fields):
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
            for dataofs in range(self.tcp['dataofs']):
                tests['dataofs'].append(TCP(dataofs=dataofs))
            for reserved in range(self.tcp['reserved']):
                tests['reserved'].append(TCP(reserved=reserved))
            for flags in range(self.tcp['flags']):
                tests['flags'].append(TCP(flags=flags))
            
            # For other fields, try max_tests random values
            seq_samples = random.sample(range(self.tcp['seq']), max_tests)
            for seq_sample in seq_samples:
                tests['seq'].append(TCP(seq=seq_sample))
            ack_samples = random.sample(range(self.tcp['ack']), max_tests)
            for ack_sample in ack_samples:
                tests['ack'].append(TCP(ack=ack_sample))
            window_samples = random.sample(range(self.tcp['window']), max_tests)
            for window_sample in window_samples:
                tests['window'].append(TCP(window=window_sample))
            urgptr_samples = random.sample(range(self.tcp['urgptr']), max_tests)
            for urgptr_sample in urgptr_samples:
                tests['urgptr'].append(TCP(urgptr=urgptr_sample))

            for field, test in tests.items():
                if field in self.fields: # only test user-specified fields
                    for packet in test:
                        sess.send(IP()/packet/Raw(load=self.payload))

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
                sess.send(IP()/packet/Raw(load=self.payload))
            
            sess.close()
