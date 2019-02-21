import random

from scapy.all import *

class TCPSession:
    def __init__(self, src, dst, sport, dport):
        self.src = src
        self.dst = dst
        self.sport = sport
        self.dport = dport

        self.seq = random.randint(0, 65536)
        self.ack = 0

        self.timeout = 3

        self.ip = IP(src=self.src, dst=self.dst)
    
    def connect(self):
        # Send SYN
        SYN = TCP(sport=self.sport, dport=self.dport, flags='S', seq=self.seq)
        self.seq += 1

        # Receive SYNACK
        SYNACK = sr1(self.ip/SYN, timeout=self.timeout)
        if not SYNACK: # or SYNACK.flags != 'SA':
            print("Error: Unable to connect.")
            return False
        # self.seq = SYNACK.ack
        self.ack = SYNACK.seq + 1

        # Send ACK
        ACK = TCP(sport=self.sport, dport=self.dport, flags='A', seq=self.seq, ack=self.ack)
        # self.seq += 1
        send(self.ip/ACK)

        print("Connected!")
        return True

    def close(self):
        # Send FIN
        FIN = TCP(sport=self.sport, dport=self.dport, flags='F', seq=self.seq)
        self.seq += 1

        # Receive FINACK
        FINACK = sr1(self.ip/FIN, timeout=self.timeout)
        if not FINACK: # or FINACK.flags != 'FA':
            print("Error: Unable to close.")
            return False
        self.ack = FINACK.seq + 1

        # Send ACK
        ACK = TCP(sport=self.sport, dport=self.dport, flags='A', seq=self.seq, ack=self.ack)
        # self.seq += 1
        send(self.ip/ACK)
        
        print("Closed. Bye!")
        return True
    
    def send(self, packet):
        packet.src = self.src
        packet.dst = self.dst
        packet.payload.sport = self.sport
        packet.payload.dport = self.dport

        packet.payload.flags = "PA" # unless fuzzing tcp flags
        packet.payload.seq = self.seq # unless fuzzing tcp seq
        packet.payload.ack = self.ack # unless fuzzing tcp ack

        # Send packet
        self.seq += len(packet.payload.payload) # size of tcp payload

        # Receive ACK
        ACK = sr1(packet, timeout=self.timeout)
        if not ACK: # or ACK.flags != 'A':
            print("Error: Unable to send.")
            return False
        self.ack = ACK.seq + 1

        print("Packet sent.")
        return True
