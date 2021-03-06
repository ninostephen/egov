#!/usr/bin/python3

# Developed by Nino Stephen Mathew ( ninosm12[at]gmail[dot]com )
# Blockchain Module

from uuid import uuid4
from json import load
from json import dump
from json import dumps
from hashlib import sha256
from datetime import datetime
from collections import OrderedDict
from blockCrypto import signTransaction
from blockCrypto import verifyTransaction
from blockCrypto import getPublicKey

# Block Structure
'''
block = {
    Block Number : blockNo,
    UUID of request : requestID,
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
    def __init__(self, blockNo, requestID, userID, officialID, unitID, headers, transaction):
        self.blockNo = blockNo
        self.requestID = requestID
        self.userID = userID
        self.officialID = officialID
        self.userID = userID
        self.headers = headers
        self.transaction = transaction
        self.next = None

class Blockchain:
    def __init__(self):
        headers = OrderedDict({
            "main" : {
                "signerID" : "Genesis Block Admin"
            }
        })
        transaction = OrderedDict({
            "main" : {
                "data" : "Genesis Block",
                "hash" : "a56119e7bc8f53e86dce305298b6795d4e534b5a9df0bf3b8ce7a149a4010493"
            }
        })
        self.head = Block(blockNo = 0, requestID = uuid4(),  userID = "admin", officialID = "admin", unitID = "admin", headers = headers, transaction = transaction)
        data = OrderedDict({
            "headers" : dumps(headers),
            "transcation" : dumps(transaction)
        })
        chain = {}
        chain['main'] = []
        chain['main'].append(data)
        with open('chain/chain.json',"a") as chainfile:
            dump(chain,chainfile)
            chainfile.write('\n')
    def addBlock(self, newBlock):
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
        #print(total)
        return total

    def createBlock(self, username,type, requestID, userID, officialID, unitID, data):
        blockNo = self.length() + 1
        SignerID = username
        headers = OrderedDict({
            "block Number" : blockNo,
            "request"      : requestID,
            "requestee"    : userID,
            "official"     : officialID,
            "Unit"         : unitID
        })
        tHash = self.getTHash(dumps(headers).encode('ascii') + dumps(data).encode('ascii'))
        dHash = self.getTHash(dumps(data).encode('ascii'))
        pHash = self.getPHash(blockNo - 1)
        rHash = self.getRHash(requestID)
        r_CurrentTransaction, s_CurrentTransaction, tHash = signTransaction(username = SignerID, transactionData = tHash, type = type)

        r_PreviousTransaction, s_PreviousTransaction , pHash = signTransaction(username = SignerID, transactionData = pHash, type = type)

        r_RelatedPreviousTransaction, s_RelatedPreviousTransaction, rHash = signTransaction(username = SignerID, transactionData = rHash, type = type)

        transaction = OrderedDict({
            "main" : {
                "signer" : SignerID, # User/Official
                "Hash" : tHash, #SHA256
                "dHash" : dHash,
                "r" : r_CurrentTransaction ,
                "s" : s_CurrentTransaction
            },
            "previousRHash" : {
                "signer" : SignerID, # User/Official
                "Hash" : rHash, #SHA256
                "r" : r_RelatedPreviousTransaction,
                "s" : s_RelatedPreviousTransaction
            },
            "previousHash" : {
                "signer" : SignerID, # User/Official
                "Hash" : pHash, #SHA256
                "r" : r_PreviousTransaction,
                "s" : s_PreviousTransaction
            }
        })

        newBlock = Block(blockNo, requestID = requestID, userID = userID, officialID = officialID, unitID = unitID, headers = headers, transaction = transaction)
        data = OrderedDict({
            "headers" : dumps(headers),
            "transcation" : dumps(transaction)
        })
        self.addBlock(newBlock)
        chain = {}
        chain['main'] = []
        chain['main'].append(data)
        with open('chain/chain.json',"a") as chainfile:
            dump(chain, chainfile)
            chainfile.write('\n')
            

    def getTHash(self, data):
        return sha256(data).hexdigest()

    def getRHash(self, requestID):
        cur = self.head
        lastRBlock =  cur.blockNo
        while (cur.next):
            if cur.requestID  == requestID :
                lastRBlock = cur.blockNo
            cur = cur.next
        cur = self.head
        while (cur.blockNo != lastRBlock):
            cur = cur.next
        return sha256(dumps(cur.headers).encode('ascii') + dumps(cur.transaction).encode('ascii')).hexdigest()

    def getPHash(self, blockNo):
        cur = self.head
        while(cur.blockNo != blockNo):
            cur = cur.next
        return  sha256(dumps(cur.headers).encode('ascii') + dumps(cur.transaction).encode('ascii')).hexdigest()


    def displayChain(self):
#        elems = []
        cur = self.head
#        elem = []
        while cur.next != None:
            print(dumps(cur.headers, indent=4, sort_keys=False) , dumps(cur.transaction, indent=4, sort_keys=True))
            cur = cur.next
        print(dumps(cur.headers, indent=4, sort_keys=False) , dumps(cur.transaction, indent=4, sort_keys=True))
#        with open('chain/chain.json') as json_file:
#            chain = load(json_file)
#            for part in chain['main']:
#                print(part['headers'])
#                print(part['transaction'])



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
