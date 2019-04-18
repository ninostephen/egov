#!/usr/bin/python3

# Developed by Nino Stephen Mathew ( ninosm12[at]gmail[dot]com )
# Blockchain Module

from uuid import uuid4
from json import dumps
from hashlib import sha256
from datetime import datetime
from collections import OrderedDict
from urllib.parse import urlparse
from blockCrypto import verifyTransaction
from blockCrypto import getPublicKey

class Blockchain:

    def __init__(self):
        self.transactions = []
        self.chain = []
        self.nodes=()
        self.nodeId = str(uuid4()).replace('-','')
        #Create Genesis Block
        self.createBlock("Genesis")

#    def registerNode(self, nodeUrl):
#        parsedUrl = urlparse(nodeUrl)
#        if parsedUrl.netloc:
#            self.nodes.add(parsedUrl.netloc)
#        elif parsedUrl.path:
#            self.nodes.add(parsedUrl.path)
#        else :
#            raise ValueError("Invalid Url")

    def verify(self, username, r, s, transaction):
        publicKey = getPublicKey(username)
        return verifyTransaction(r, s, transaction, publicKey)

    def addTransaction(self, senderAddr, recipientAddr, transactionData, r, s):
        transaction = OrderedDict(
            {
                'senderAddr' : senderAddr,
                'recipientAddr' : recipientAddr,
                'data' : dumps(transactionData)
            }
        )
        transaction = dumps(transaction)
        verified = verify(username, r, s, transaction)
        if varified:
            self.transactions.append(transaction)
            return len(self.chain) + 1
        return False

    def createBlock(self, previousHash):
        # hash(self.chain[-1])
        block = {
            'block number' : str(len(self.chain) + 1),
            'timestamp' : datetime.now(),
            'transactions' : dumps(self. transactions),
            'previous related hash' : previousRHash,
            'previous hash' : previousHash
        }
        self.transactions = []
        self.chain.append(block)
        return block

    def hash(self, block):
        blockString = dumps(block, sort_keys=True).encode()
        return sha256(blockString).hexdigest()

    def validateChain(self, chain):
        for index in range(1, len(chain) + 1):
            lastBlock = chain[index - 1]
            currentBlock = chain[index]
            if currentBlock['previousHash'] != self.hash(lastBlock):
                return False
