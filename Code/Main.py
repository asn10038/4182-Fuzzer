'''run Main.py [args] to run the program'''
import logging
from optparse import OptionParser

from fuzzer import IPFuzzer, TCPFuzzer, AppFuzzer, utils

# class Main:
#     def run(self):
#         print("Hello World")

def get_option_parser():
    ret = OptionParser()
    ret.set_usage("python3 Main.py [options] [ip/tcp/app] [host] [port]")
    ret.add_option("-f", "--fields", dest="fields", 
        help="The layers to fuzz for default tests", default="all")
    ret.add_option("-l", "--layer", dest="layer", 
        help="The layer to fuzz (ip/tcp/app), default is ip", default="ip")
    ret.add_option("-m", "--max_tests", dest="max_tests",
        help="Maximum number of tests to run for a field, default 256", default=256)
    ret.add_option("-p", "--payload_file", dest="payload",
        help="The payload file", default="payload.txt")
    ret.add_option("-v", "--verbose", dest="verbose", action="store_true",
        help="Include debug print statements", default=False)
    return ret

def run():
    parser = get_option_parser()
    (options, args) = parser.parse_args()

    if len(args) != 2:
        exit()

    host, port = args[0], args[1]

    # Parse fields
    fields = options.fields.split(',')

    # Read the payload
    preader = utils.PayloadFileReader(options.payload)
    payload = preader.read_payload()

    if options.layer == "ip":
        logging.info("Starting IP Fuzzer....")
        f = IPFuzzer.IPFuzzer(host, port, payload, options.max_tests, fields)
        f.run_default()
    
    elif options.layer == "tcp":
        logging.info("Starting TCP Fuzzer....")
        # f = TCPFuzzer.TCPFuzzer(host, port)
        # f.run()
    
    elif options.layer == "app":
        logging.info("Starting Application layer Fuzzer....")
        # f = AppFuzzer.AppFuzzer(host, port)
        # f.run()
    
    else:
        logging.critical("Unknown layer! Program exiting...")

if __name__ == '__main__':
    # main = Main()
    # main.run()
    run()
