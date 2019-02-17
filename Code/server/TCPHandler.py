import socketserver
import logging

class TCPHandler(socketserver.StreamRequestHandler):
    '''The request handler for the server'''

    def handle(self):
        # self.data = self.rfile.readline().strip()
        # for x in range(5):
            # self.data += self.rfile.readline().strip()
        valid_payload = False
        self.data = self.request.recv(1024).strip()
        logging.debug("{} wrote: {}".format(self.client_address[0], self.data))

        self.pattern = self.server.pattern
        if(self.payload_starts_w_pattern(self.data)):
            valid_payload = True
            logging.debug("Valid PAYLOAD!!!!")
        else:
            logging.debug("INVALID PAYLOAD :(")

        if valid_payload:
            self.server.validCount += 1
            self.wfile.write(bytearray.fromhex("00"))
        else:
            self.server.invalidCount += 1
            self.wfile.write(bytearray.fromhex("FF"))



    def payload_starts_w_pattern(self, data):
        bytes = bytearray(data)
        print(bytes)
        for x in range(len(self.pattern)):
            if data[x] != self.pattern[x]:
                return False
        return True
