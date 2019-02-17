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

        tcpServer = socketserver.TCPServer((self.HOST,
                                     self.PORT),
                                     tcp.TCPHandler)
        tcpServer.pattern = self.PATTERN
        tcpServer.validCount = 0
        tcpServer.invalidCount = 0
        with tcpServer as server:
            try:
                print("CTRL+C to exit")
                server.serve_forever();
            except KeyboardInterrupt:
                if self.OUTFILE.name != '<stdout>':
                    logging.debug("Outputting Statistics to: {}".format(self.OUTFILE.name))
                self.output_statistics(tcpServer.validCount, tcpServer.invalidCount)
                print("\nShutting Down")
                raise SystemExit

    def output_statistics(self, validCount, invalidCount):
        self.OUTFILE.write("Valid Packets Received: {}\n".format(validCount))
        self.OUTFILE.write("Invalid Packets Received: {}\n".format(invalidCount))
