import socketserver
import logging

class TCPHandler(socketserver.StreamRequestHandler):
    '''The request handler for the server'''

    def handle(self):
        while 1:
            try:
                valid_payload = False
                self.data = self.request.recv(1024).strip()
                # keep reading until you've read all of the client information
                if not self.data:
                    break
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
            except:
                print("Error in receiving packet. Ignoring...")
                continue


    def payload_starts_w_pattern(self, data):
        bytes = bytearray(data)
        print(bytes)
        for x in range(len(self.pattern)):
            if data[x] != self.pattern[x]:
                return False
        return True
