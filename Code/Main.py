'''run Main.py [args] to run the program'''
import logging
from optparse import OptionParser

from fuzzer import IPFuzzer, TCPFuzzer, AppFuzzer, utils

# class Main:
#     def run(self):
#         print("Hello World")

def get_option_parser():
    ret = OptionParser()
    ret.set_usage("python3 Main.py [options] [ip/tcp/app] [dhost] [dport]")
    ret.add_option("-f", "--fields", dest="fields", 
        help="The layers to fuzz for default tests", default="all")
    ret.add_option("-m", "--max_tests", dest="max_tests",
        help="Maximum number of tests to run for a field, default 256", default=256)
    ret.add_option("-p", "--payload_file", dest="payload",
        help="The payload file", default="payload.txt")
    ret.add_option("-s", "--source_host", dest="shost",
        help="The source ip address", default="localhost")
    ret.add_option("-t", "--source_port", dest="sport",
        help="The source port", default=1365)
    ret.add_option("-v", "--verbose", dest="verbose", action="store_true",
        help="Include debug print statements", default=False)
    return ret

def run():
    parser = get_option_parser()
    (options, args) = parser.parse_args()

    if len(args) != 3:
        parser.print_help()
        exit()

    layer, host, port = args[0], args[1], args[2]

    if layer.lower() not in ('ip', 'tcp', 'app'):
        parser.print_help()
        exit()

    # Parse fields
    fields = options.fields.split(',')

    # Read the payload
    preader = utils.PayloadFileReader(options.payload)
    payload = preader.read_payload()

    src = (options.shost, int(options.sport))
    dst = (host, int(port))

    if layer == "ip":
        logging.info("Starting IP Fuzzer....")
        f = IPFuzzer.IPFuzzer(src, dst, payload, options.max_tests, fields)
        f.run_default()
    
    elif layer == "tcp":
        logging.info("Starting TCP Fuzzer....")
        # f = TCPFuzzer.TCPFuzzer(host, port)
        # f.run()
    
    else:
        logging.info("Starting Application layer Fuzzer....")
        # f = AppFuzzer.AppFuzzer(host, port)
        # f.run()

if __name__ == '__main__':
    # main = Main()
    # main.run()
    run()
