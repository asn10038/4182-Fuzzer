import logging
import sys

class ShutdownHandler(logging.Handler):
    def emit(self, record):
        logging.shutdown()
        print("SHUTDOWN ON CRITICAL ERROR")
        raise SystemExit

class LogCreator:
    def __init__(self, verbose):
        self.verbose = verbose
        self.setup_logger()

    def setup_logger(self):
        if self.verbose:
            logging.basicConfig(format='%(asctime)s,%(msecs)d %(levelname)-8s [%(filename)s:%(lineno)d] %(message)s',
            datefmt='%Y-%m-%d:%H:%M:%S',
            level=logging.DEBUG)
        else:
            logging.basicConfig(format='%(asctime)s,%(msecs)d %(levelname)-8s [%(filename)s:%(lineno)d] %(message)s',
            datefmt='%Y-%m-%d:%H:%M:%S')
        logging.getLogger().addHandler(ShutdownHandler(level=50))

class ServerLogger:
    @staticmethod
    def get_server_logger():
        return logging.getLogger(__name__)
    @staticmethod
    def log(message, level):
        if level == "debug":
            logging.debug(message)
        elif level == "info":
            logging.info(message)
        elif level == "warning":
            logging.warning(message)
        elif level == "error":
            logging.warning(message)
        elif level == "critical":
            logging.critical(message)
        else:
            logging.debug(message)
