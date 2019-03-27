''' This is the app fuzzer '''
import logging
import random
import fuzzer.utils as utils
from scapy.all import *
import socket 

class AppFuzzer:

    def __init__(self, host, port, numTests=5, minPayloadSize=10, maxPayloadSize=10, payloadFilePath='', maxNumTests=1024):
       self.numTests = numTests
       self.minPayloadSize = minPayloadSize
       self.maxPayloadSize = maxPayloadSize
       self.payloadFilePath = payloadFilePath
       self.payloads = self.getPayloads()
       self.maxNumTests = maxNumTests
       self.host = host
       self.port = port
       self.validCount = 0
       self.invalidCount = 0
       self.MAXPSIZE = 1000

    def getPayloads(self):
        if self.payloadFilePath == '':
            return self.getRandomPayloads(self.minPayloadSize, self.maxPayloadSize, self.numTests)
        else:
            return self.readPayloads()

    def readPayloads(self):
        res = []
        pfr = utils.PayloadFileReader("")
        logging.info("Reading payloads from: " + self.payloadFilePath)
        with open(self.payloadFilePath) as inFile:
            for line in inFile:
                hexBytes = pfr.get_hex(line)
                res.append(hexBytes)
        return res

    def getRandomPayloads(self, minSize, maxSize, numTests):
        logging.info("Generating {} random payloads: ".format(numTests))
        res = []
        for x in range(numTests):
            if minSize != maxSize:
                payloadSize = random.randint(minSize, maxSize)
            else:
                payloadSize = minSize
            intPayload = []

            for x in range(payloadSize):
                intPayload.append(x)

            logging.info("Created Payload: {}".format(intPayload))
            res.append(bytearray(intPayload))
        return res

    def run(self):
        # This runs the fuzzer
        for ind, payload in enumerate(self.payloads):
            if ind > self.maxNumTests:
                print("Too many tests. Skipping the rest...")
                break
            if len(payload) > self.MAXPSIZE:
                print("Payload too long...ignoring: {}".format(payload))
                continue

            logging.debug("Sending payload: {}".format(payload))
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.connect((self.host, int(self.port)))
                sock.sendall(payload)
                received = str(sock.recv(1024)) 
                logging.debug("Received: {}".format(received))
                if  'ff' in str(received):
                    self.invalidCount += 1
                elif '00' in str(received):
                    self.validCount += 1
        print('Total Tests: {}'.format(self.validCount + self.invalidCount))
        print('Valid Count: {} \n Invalid Count: {}'.format(self.validCount, self.invalidCount))
