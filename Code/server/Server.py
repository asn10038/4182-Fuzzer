import socketserver
import server.TCPHandler as tcp
import logging

class Server:

    def __init__(self, host, port, pattern, out_file):
        self.HOST = host
        self.PORT = port
        self.PATTERN = pattern
        self.OUTFILE = out_file

    def run(self):
        logging.info("Starting server on {}:{}...".format(self.HOST, self.PORT))
        logging.debug("Searching for pattern: {}".format(self.PATTERN))
        # Needed this otherwise the process hogs the port for a while
        socketserver.TCPServer.allow_reuse_address = True
        with socketserver.TCPServer((self.HOST,
                                     self.PORT),
                                     tcp.TCPHandler) as server:
            try:
                print("CTRL+C to exit")
                server.serve_forever();
            except KeyboardInterrupt:
                print("\nShutting Down")
                raise SystemExit
