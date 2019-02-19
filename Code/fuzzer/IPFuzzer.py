import random

from scapy.all import IP, TCP, Raw, send

class IPFuzzer:

    def __init__(self, host, port, payload, max_tests, fields):
        self.host = host
        self.port = int(port)
        self.payload = payload
        self.max_tests = max_tests
        self.fields = set(fields)
    
    def run_default(self):
        tests = {}

        # For fields with few bits, try every possible value
        tests['version'] = IP(dst=self.host, version=range(0x10))/TCP(dport=self.port)/Raw(load=self.payload)
        tests['ihl'] = IP(dst=self.host, ihl=range(0x10))/TCP(dport=self.port)/Raw(load=self.payload)
        tests['tos'] = IP(dst=self.host, tos=range(0x100))/TCP(dport=self.port)/Raw(load=self.payload)
        tests['flags'] = IP(dst=self.host, flags=[0, 1, 2, 3, 4, 5, 6, 7])/TCP(dport=self.port)/Raw(load=self.payload)
        tests['ttl'] = IP(dst=self.host, ttl=range(0x100))/TCP(dport=self.port)/Raw(load=self.payload)
        tests['proto'] = IP(dst=self.host, proto=range(0x100))/TCP(dport=self.port)/Raw(load=self.payload)
        
        # For other fields, try max_tests random values
        len_samples = random.sample(range(0x10000), self.max_tests)
        tests['len'] = IP(dst=self.host, len=len_samples)/TCP(dport=self.port)/Raw(load=self.payload)
        id_samples = random.sample(range(0x10000), self.max_tests)
        tests['id'] = IP(dst=self.host, id=id_samples)/TCP(dport=self.port)/Raw(load=self.payload)
        frag_samples = random.sample(range(0x2000), self.max_tests)
        tests['frag'] = IP(dst=self.host, frag=frag_samples)/TCP(dport=self.port)/Raw(load=self.payload)

        for field, test in tests.items():
            if 'all' in self.fields or field in self.fields: # only test user-specified fields
                send(test)
