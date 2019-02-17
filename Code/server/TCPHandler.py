import socketserver
import logging

class TCPHandler(socketserver.StreamRequestHandler):
    '''The request handler for the server'''

    def handle(self):
        # self.data = self.rfile.readline().strip()
        # for x in range(5):
            # self.data += self.rfile.readline().strip()
        self.data = self.request.recv(1024).strip()

        self.pattern = self.server.pattern
        if(self.payload_starts_w_pattern(self.data)):
            print("Valid PAYLOAD!!!!")
        else:
            print("INVALID PAYLOAD :(")

        logging.debug("{} wrote: {}".format(self.client_address[0], self.data))
        self.wfile.write(bytearray("SERVER RESPONSE HERE\n", 'utf-8'))

    def payload_starts_w_pattern(self, data):
        bytes = bytearray(data)
        print(bytes)
        for x in range(len(self.pattern)):
            if data[x] != self.pattern[x]:
                return False
        return True
