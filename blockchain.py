#!/usr/bin/python3

# Developed by Nino Stephen Mathew ( ninosm12[at]gmail[dot]com )
# Blockchain Module

from uuid import uuid4
from json import dumps
from hashlib import sha256
from datetime import datetime
from collections import OrderedDict
from blockCrypto import verifyTransaction
from blockCrypto import getPublicKey

# Block Structure
'''
block = {
    Block Number : blockNo,
    UUID of Requestee : UserID,
    UUID of Official : OfficialID,
    UUID of Unit : UnitID,
    Transaction : {
        signer : SignerID, # User/Official
        Hash : 3abd011ccc65c133f173bb7bc9aefa910cca94165038da1c3ea23f8f30e11cef, #SHA256
        r : ,
        s :
    },
    previousRHash : {
        signer : SignerID, # User/Official
        Hash : 3abd011ccc65c133f173bb7bc9aefa910cca94165038da1c3ea23f8f30e11cef, #SHA256
        r : ,
        s :
    },
    previousHash : {
        signer : SignerID, # User/Official
        Hash : 3abd011ccc65c133f173bb7bc9aefa910cca94165038da1c3ea23f8f30e11cef, #SHA256
        r : ,
        s :
    }
}
'''

# Block Class
class Block:
    def __init__(self, blockNo = 0, data = "Genesis", previousRHash = '0x0', previousHash = '0x0'):
        self.blockNo = blockNo
        self.data = data
        self.previousRHash = previousRHash
        self.previousHash = previousHash
        self.next = None

class Blockchain:
    def __init__(self):
        self.head = Block()

    def addBlock(self, data, previousRHash, previousHash):
        blockNo = length() + 1
        newBlock = Block(blockNo, data, previousRHash, previousHash)
        cur = self.head
        while cur.next != None:
            cur = cur.next
        cur.next = newBlock

    def length(self):
        cur = self.head
        total = 0
        while cur.next != None:
            total = total + 1
            cur = cur.next
        print(total)
        return total

    def displayChain(self):
        elems = []
        cur = self.head
        while cur.next != None:
            elems.append(cur.blockNo)
            cur = cur.next
        elems.append(cur.blockNo)
        print(elems)
        return elems


'''
#class Blockchain:
#
#    def __init__(self):
#        self.transactions = []
#        self.chain = []
#        self.nodes=()
#        self.nodeId = str(uuid4()).replace('-','')
#        #Create Genesis Block
#        self.createBlock("Genesis","00")
#
#    def registerNode(self, nodeUrl):
#        parsedUrl = urlparse(nodeUrl)
#        if parsedUrl.netloc:
#            self.nodes.add(parsedUrl.netloc)
#        elif parsedUrl.path:
#            self.nodes.add(parsedUrl.path)
#        else :
#            raise ValueError("Invalid Url")
#
#    def verify(self, username, r, s, transaction):
#        publicKey = getPublicKey(username)
#        return verifyTransaction(r, s, transaction, publicKey)
#
#    def addTransaction(self, senderAddr, recipientAddr, transactionData, r, s):
#        transaction = OrderedDict(
#            {
#                'senderAddr' : senderAddr,
#                'recipientAddr' : recipientAddr,
#                'data' : dumps(transactionData)
#            }
#        )
#        transaction = dumps(transaction)
#        print(transaction)
#        verified = verifyTransaction(r, s, transaction, senderpubKey=getPublicKey(username=senderAddr, type='user'))
#        if varified:
#            self.transactions.append(transaction)
#            return len(self.chain) + 1
#        return False
#
#    def createBlock(self, previousRHash, previousHash):
#        # hash(self.chain[-1])
#        block = {
#            'block number' : str(len(self.chain) + 1),
#            'timestamp' : datetime.now(),
#            'transactions' : dumps(self. transactions),
#            'previous related hash' : previousRHash,
#            'previous hash' : previousHash
#        }
#        self.transactions = []
#        self.chain.append(block)
#        return block
#
#    def hash(self, block):
#        blockString = dumps(block, sort_keys=True).encode()
#        return sha256(blockString).hexdigest()
#
#    def validateChain(self, chain):
#        for index in range(1, len(chain) + 1):
#            lastBlock = chain[index - 1]
#            currentBlock = chain[index]
#            if currentBlock['previousHash'] != self.hash(lastBlock):
#                return False
'''
