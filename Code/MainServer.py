''' This is the entry point to running the server '''
import sys
import server.Server as ser


def usage():
    usage = """python MainServer.py [host] [port]\n
              python MainServer.py\n
              e.x. python MainServer.py localhost 5000"""

def run(host="localhost", port=8000):
    s = ser.Server(host, port)
    s.run()

if __name__ == '__main__':
    if len(sys.argv) == 3:
        run(sys.argv[1], sys.argv[2])
    elif len(sys.argv) == 1:
        run()
    else:
        usage()
