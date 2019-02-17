from scapy.all import IP, TCP, Raw, send

class IPFuzzer:

    def __init__(self, host, port, payload):
        self.host = host
        self.port = int(port)
        self.payload = payload
    
    def run_default(self):
        send(IP(dst=self.host, version=range(0x10))/TCP(dport=self.port)/Raw(load=self.payload))
        send(IP(dst=self.host, ihl=range(0x10))/TCP(dport=self.port)/Raw(load=self.payload))
        send(IP(dst=self.host, tos=range(0x100))/TCP(dport=self.port)/Raw(load=self.payload))
        # TODO: len and id field have 16 bits, iterate or random?
        send(IP(dst=self.host, flags=[0, 1, 2, 3, 4, 5, 6, 7])/TCP(dport=self.port)/Raw(load=self.payload))
        # TODO: frag field has 13 bits, iterate or random?
        # send(IP(dst=self.host, frag=range(0x2000))/TCP(dport=self.port)/Raw(load=self.payload))
        send(IP(dst=self.host, ttl=range(0x100))/TCP(dport=self.port)/Raw(load=self.payload))
        send(IP(dst=self.host, proto=range(0x100))/TCP(dport=self.port)/Raw(load=self.payload))
