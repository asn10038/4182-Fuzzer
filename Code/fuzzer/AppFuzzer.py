''' This is the app fuzzer '''
import logging
import random
import fuzzer.TCPSession as ts
import fuzzer.utils
from scapy.all import *

class AppFuzzer:

    def __init__(self, tcpSession, numTests=5, minPayloadSize=10, maxPayloadSize=10, payloadFilePath=''):
       self.numTests = numTests
       self.minPayloadSize = minPayloadSize
       self.maxPayloadSize = maxPayloadSize
       self.payloadFilePath = payloadFilePath
       self.TCPSession = tcpSession
       self.payloads = self.getPayloads()

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
        if self.TCPSession.connect():
            for payload in self.payloads:
                logging.info("Sending payload: {}".format(payload))
                packet = self.TCPSession.ip / TCP() / Raw(load=payload)
                sendp(packet)

if __name__ == '__main__':
    print("Running the application layer fuzzing")
    sess = ts.TCPSession("127.0.0.1", "127.0.0.1", 3000, 8000, timeout=0.1)
    af = AppFuzzer(sess)
    af.run()
