import random
from threading import Thread

from scapy.all import *

class Sniffer(Thread):
    def __init__(self, session, _filter):
        super().__init__()

        # self.timeout = 5 # give server 5 seconds to send fin, otherwise close from client
        
        self.session = session
        self.filter = _filter

    def run(self):
        print("Sniffer started.")
        sniff(
            prn=self.session.send_ack, # Acknowledge received packets
            filter=self.filter,
            # timeout=self.timeout,
            # stop_filter=lambda x: x[TCP].flags.F # Stop when received fin from server
            stop_filter=lambda _: not self.session.connected # Stop when connection is closed
        )
        print("Sniffer exited.")

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

        _filter = "src host " + dst + " and src port " + str(dport)
        _filter = "tcp[tcpflags] & (tcp-push|tcp-fin) != 0 and " + _filter
        self.sniffer = Sniffer(self, _filter)

        self.connected = False
        self.active_close = False
    
    def send_ack(self, packet):
        # print(packet.show())
        # Receive PSHACK or FINACK
        self.ack = packet.seq + 1

        if packet[TCP].flags.P:
            # Print response from server!
            print("Response from server: {}".format(packet[Raw].load))

        if packet[TCP].flags.P: # PA or FPA
            # Send ACK
            ACK = TCP(sport=self.sport, dport=self.dport, flags='A', seq=self.seq, ack=self.ack)
            send(self.ip/ACK)
        
        else: # FA
            # print(self.active_close, packet[TCP].flags)
            if self.active_close: # Received 2nd msg in handshake
                # Send ACK
                ACK = TCP(sport=self.sport, dport=self.dport, flags='A', seq=self.seq, ack=self.ack)
                send(self.ip/ACK)
                self.active_close = False
                self.connected = False
                print("Connection closed. Bye!")

            else: # Received 1st msg in handshake (passive close)
                # Send FINACK
                FINACK = TCP(sport=self.sport, dport=self.dport, flags='FA', seq=self.seq, ack=self.ack)

                # Receive ACK
                ACK = sr1(self.ip/FINACK, timeout=self.timeout)
                if not ACK or not ACK[TCP].flags.A:
                    print("Error: Close connection failed.")
                else:
                    self.connected = False
                    print("Connection closed. Bye!")

    def connect(self):
        """ Connect to server """
        if self.connected:
            print("Error: Already connected.")
            return False
        
        # Send SYN
        SYN = TCP(sport=self.sport, dport=self.dport, flags='S', seq=self.seq)
        self.seq += 1

        # Receive SYNACK
        SYNACK = sr1(self.ip/SYN, timeout=self.timeout)
        if not SYNACK or SYNACK[TCP].flags != 'SA':
            print("Error: Unable to connect.")
            return False
        self.ack = SYNACK.seq + 1

        # Send ACK
        ACK = TCP(sport=self.sport, dport=self.dport, flags='A', seq=self.seq, ack=self.ack)
        # self.seq += 1
        send(self.ip/ACK)

        # Start sniffer
        self.sniffer.start()

        print("Connected!")
        self.connected = True
        return True

    def close(self):
        """ Active close from client """
        if not self.connected:
            print("Error: No connection to close.")
            return False
        
        # Send FIN
        FIN = TCP(sport=self.sport, dport=self.dport, flags='FA', seq=self.seq, ack=self.ack)
        self.seq += 1

        send(self.ip/FIN)
        print("Sent FIN to server.")
        self.active_close = True # TODO: Fix concurrency problem
        return True

        # Receive FINACK
        # FINACK = sr1(self.ip/FIN, timeout=self.timeout)
        # if not FINACK or FINACK[TCP].flags != 'FA':
        #     print("Error: Unable to close.")
        #     return False
        # self.ack = FINACK.seq + 1

        # Send ACK
        # ACK = TCP(sport=self.sport, dport=self.dport, flags='A', seq=self.seq, ack=self.ack)
        # self.seq += 1
        # send(self.ip/ACK)
        
        # print("Closed. Bye!")
        # self.connected = False
        # return True
    
    def send(self, packet):
        """ Send packet to server """
        if not self.connected:
            print("Error: No connection.")
            return False
        
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
        if not ACK or not ACK[TCP].flags.A:
            print("Error: Unable to send.")
            return False
        self.ack = ACK.seq + 1

        print("Packet sent.")
        return True
