import re
import logging

class PayloadFileReader:
    def __init__(self, path):
        self.path = path
        self.MAX_PLENGTH = 1000
    
    def read_payload(self):
        '''Returns the pattern from the file. Reads it as a string of hex bytes
           ignoring the white space'''

        try:
            with open(self.path) as input_file:
                #remove white space from file
                return self.get_hex(input_file.read())

        except FileNotFoundError:
            logging.critical("Pattern File Not Found: {}".format(path))

    def get_hex(self, input_string):
        '''Turns the hex pattern read as a string to a list of bytes'''
        if input_string is None:
            logging.critical("Pattern is None...exiting")

        if len(input_string) == 0:
                logging.critical('Error: Pattern has length 0')

        if len(input_string) > self.MAX_PLENGTH:
                logging.critical('''Error: Pattern length {}\n
                      Longest Pattern Allowed {}'''
                .format(len(input_string), self.MAX_PLENGTH))

        try:
            cleaned_input_string = re.sub("\s", '', input_string)
            return bytearray.fromhex(cleaned_input_string)
        except ValueError:
            logging.critical('''Pattern contains non Hex Pattern \n
                   Pattern:{}'''.format(input_string))
