'''run Main.py [args] to run the program'''
import logging
from optparse import OptionParser

import yaml

from fuzzer import IPFuzzer, TCPFuzzer, AppFuzzer, utils

def get_option_parser():
    ret = OptionParser()
    ret.set_usage("python3 Main.py [options] [ip/tcp/app] [dhost] [dport]")
    ret.add_option("-c", "--config_file", dest="config_file",
        help="The configuration file", default="config.yml")
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

    # Parse the configuration file
    with open(options.config_file, 'r') as config_file:
        cfg = yaml.safe_load(config_file)
    
    cfg_basics = cfg['basics']
    cfg_advanced = cfg['advanced']

    src = (cfg_basics['host'], int(cfg_basics['port']))
    dst = (host, int(port))

    mode = cfg_basics['mode']
    if mode not in ('default', 'custom'):
        print("Unknown mode in configuration file.")
        exit()

    # Read the payload
    preader = utils.PayloadFileReader(cfg_basics['payload_file'])
    payload = preader.read_payload()

    test_file = cfg_basics['test_file']

    max_tests_default = cfg_basics['max_tests_default']
    max_tests_custom = cfg_basics['max_tests_custom']

    # Parse fields
    ip_fields = cfg_advanced['ip_fields']
    tcp_fields = cfg_advanced['tcp_fields']

    if layer == "ip":
        logging.info("Starting IP Fuzzer....")
        f = IPFuzzer.IPFuzzer(src, dst, payload, ip_fields)
        if mode == 'default':
            f.run_default(max_tests_default)
        elif mode == 'custom':
            f.run_custom(test_file, max_tests_custom)
    
    elif layer == "tcp":
        logging.info("Starting TCP Fuzzer....")
        f = TCPFuzzer.TCPFuzzer(host, port)
        f.run_default()
    
    else:
        logging.info("Starting Application layer Fuzzer....")
        # f = AppFuzzer.AppFuzzer(host, port)
        # f.run()

if __name__ == '__main__':
    run()
