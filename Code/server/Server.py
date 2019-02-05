import socketserver
import server.TCPHandler as tcp

class Server:
    HOST = "localhost"
    PORT = 8000

    def __init__(self, host="localhost", port=8000):
        self.HOST = host
        self.PORT = port

    def run(self):
        print("Starting server on {}:{}".format(self.HOST, self.PORT))
        # Needed this otherwise the process hogs the port for a while
        socketserver.TCPServer.allow_reuse_address = True
        with socketserver.TCPServer((self.HOST,
                                     self.PORT),
                                     tcp.TCPHandler) as server:
            server.serve_forever();
