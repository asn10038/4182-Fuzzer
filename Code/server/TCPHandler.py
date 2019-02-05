import socketserver

class TCPHandler(socketserver.StreamRequestHandler):
    '''The request handler for the server'''

    def handle(self):
        self.data = self.rfile.readline().strip()
        print("{} wrote:".format(self.client_address[0]))
        print(self.data)
        self.wfile.write(bytearray("SERVER RESPONSE HERE\n", 'utf-8'))
