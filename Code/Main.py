'''run Main.py [args] to run the program'''
import logging
from optparse import OptionParser

import yaml

# only here for debugging
import fuzzer.TCPSession as ts
import fuzzer.AppFuzzer as af
from fuzzer import IPFuzzer, TCPFuzzer, utils

def get_option_parser():
    ret = OptionParser()
    ret.set_usage("python3 Main.py [options] [ip/tcp/app] [dhost] [dport]")
    ret.add_option("-c", "--config_file", dest="config_file",
        help="The configuration file", default="config.yml")
    ret.add_option("-s", "--source_host", dest="shost",
        help="The source ip address")
    ret.add_option("-t", "--source_port", dest="sport",
        help="The source port")
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
    try:
        with open(options.config_file, 'r') as config_file:
            cfg = yaml.safe_load(config_file)
    
        cfg_basics = cfg['basics']
        cfg_advanced = cfg['advanced']

        src = [cfg_basics['host'], int(cfg_basics['port'])]
        dst = (host, int(port))

        mode = cfg_basics['mode']
        if mode not in ('default', 'custom'):
            print("Unknown mode in configuration file.")
            exit()
        
        payload_file = cfg_basics['payload_file']
        test_file = cfg_basics['test_file']

        max_tests_default = cfg_basics['max_tests_default']
        max_tests_custom = cfg_basics['max_tests_custom']

        # Parse fields
        ip_fields = cfg_advanced['ip_fields']
        tcp_fields = cfg_advanced['tcp_fields']

        sniffer_timeout = cfg_advanced['sniffer_timeout']

        # Read options for app layer
        numTests = int(cfg_advanced['app_layer']['numTests'])
        minPayloadSize = int(cfg_advanced['app_layer']['minPayloadSize'])
        maxPayloadSize = int(cfg_advanced['app_layer']['maxPayloadSize'])
        if 'payloadFilePath' in cfg_advanced['app_layer']:
            payloadFilePath = cfg_advanced['app_layer']['payloadFilePath']
        else:
            payloadFilePath = ''
    
    except FileNotFoundError:
        print("Configuration file not found. Using default configuration...")

        src = ['localhost', 1365]
        dst = (host, int(port))

        mode = 'default'

        payload_file = '../SampleFiles/payload.txt'
        test_file = '../SampleFiles/test.txt'

        max_tests_default = 32
        max_tests_custom = 1024

        ip_fields = ['all']
        tcp_fields = ['all']

        sniffer_timeout = 5

        numTests = 5
        minPayloadSize = 10
        maxPayloadSize = 10
        payloadFilePath = ''

    # overwrite configuration file if host and port specified in command line options
    if options.shost:
        src[0] = options.shost
    if options.sport:
        src[1] = int(options.sport)

    # Read the payload
    preader = utils.PayloadFileReader(payload_file)
    payload = preader.read_payload()

    if layer == "ip":
        logging.info("Starting IP Fuzzer....")
        f = IPFuzzer.IPFuzzer(src, dst, payload, ip_fields, sniffer_timeout)
        if mode == 'default':
            f.run_default(max_tests_default)
        elif mode == 'custom':
            f.run_custom(test_file, max_tests_custom)
    
    elif layer == "tcp":
        logging.info("Starting TCP Fuzzer....")
        f = TCPFuzzer.TCPFuzzer(src, dst, payload, tcp_fields, sniffer_timeout)
        if mode == 'default':
            f.run_default(max_tests_default)
        elif mode == 'custom':
            f.run_custom(test_file, max_tests_custom)
    
    else:
        logging.info("Starting Application layer Fuzzer....")
        f = af.AppFuzzer(host, port, numTests=numTests, minPayloadSize=minPayloadSize, maxPayloadSize=maxPayloadSize, payloadFilePath=payloadFilePath) # , maxNumTests=max_tests_custom)
        f.run()

if __name__ == '__main__':
    run()
