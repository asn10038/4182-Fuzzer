''' This is the entry point to running the server '''
import sys
import server.Server as ser
import server.PatternFileReader as pfr
import server.ServerLogger as slogger
from pathlib import Path

from optparse import OptionParser

def get_option_parser():
    ret = OptionParser();
    ret.set_usage("python3 MainServer.py [options] [pattern_file]")
    ret.add_option("-o", "--output-file", dest="out_file",
                      help="The output file to print the counts",
                      metavar="FILE_PATH", default='sys.stdout')
    ret.add_option("-p", "--port", dest="port",
                      help="The port the server binds to. Takes and int. default is 8000", default=8000)
    ret.add_option("-s", "--host", dest="host",
                      help="The host the server binds to. Default is localhost", default="localhost")
    ret.add_option("-v", "--verbose", dest="verbose", action="store_true",
                    help="Include debug print statements", default=False)
    # TODO add a verbose option
    return ret

def run():
    parser = get_option_parser()
    (options, args) = parser.parse_args()


    # Read the arguments
    host = options.host
    port = int(options.port)
    out_file = options.out_file
    # setup the logger
    verbose = options.verbose
    slogger.LogCreator(verbose)
    if not Path(out_file).exists() and out_file != 'sys.stdout':
        slogger.ServerLogger.get_server_logger().warning("Output File {} doesn't exist.".format(out_file))

    if len(args) < 1:
        slogger.ServerLogger.get_server_logger().critical("No pattern file specified")
    if len(args) > 1:
        slogger.ServerLogger.get_server_logger().warning("Extra arguments included")

    pattern_file = args[0]
    if not Path(pattern_file).exists():
        slogger.ServerLogger.get_server_logger().critical("Pattern File doesn't exist: {}".format(pattern_file))
    # Read the pattern from the file
    preader = pfr.PatternFileReader(pattern_file)
    pattern = preader.read_pattern()


    s = ser.Server(host, port, pattern, out_file)
    s.run()

if __name__ == '__main__':
    run()
