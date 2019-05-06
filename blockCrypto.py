#!/usr/bin/python3

# Developed by Nino Stephen Mathew ( ninosm12[at]gmail[dot]com )
# Crypto Module

from fastecdsa import keys
from fastecdsa import curve
from fastecdsa import ecdsa
from hashlib import sha256
from hashlib import sha384
from hashlib import new
from base58check import b58encode

def keyGen(username, type):
    privateKeyFile = username + '_privkey.pem'
    publicKeyFile = username + '_pubkey.pem'
    privateKey = keys.gen_private_key(curve.P256)
    publicKey = keys.get_public_key(privateKey, curve.P256)
    keys.export_key(privateKey, curve = curve.P256, filepath = "keys/" + type + "Key/" +  privateKeyFile)
    keys.export_key(publicKey, curve = curve.P256, filepath = "keys/" +type + "Key/" + publicKeyFile)
    return True
    #return privateKey, publicKey

def getPublicKey(username, type):
    privateKey, publicKey = keys.import_key("keys/" + type + "Key/" + username + '_pubkey.pem')
    return str(publicKey).encode('ascii')

def signTransaction(username, transactionData, type='user'):
    privateKey, publicKey = keys.import_key("keys/" + type + "Key/" + username + '_privkey.pem')
    r, s = ecdsa.sign(transactionData, privateKey, hashfunc = sha384)
    return r, s, transactionData

def verifyTransaction(r, s, transactionData, publicKey):
    valid = ecdsa.verify((r,s), transactionData, publicKey, hashfunc = sha384)
    return valid

def generateWalletAddr(username, type):
    publicKey = getPublicKey(username,type)
    h = sha256()
    h.update(str(publicKey).encode('utf-8'))
    firstHash = h.hexdigest()
    h = new('ripemd160')
    h.update(str(firstHash).encode('utf-8'))
    ripemd160Hash = h.hexdigest()
    ripemd160HashExtd = '00' + ripemd160Hash
    h = sha256()
    h.update(str(ripemd160HashExtd).encode('utf-8'))
    hash2 = h.hexdigest()
    h.update(str(hash2).encode('utf-8'))
    hash3 = h.hexdigest()
    fourBytes = hash3[:8]
    binAddr = ripemd160HashExtd + fourBytes
    walletAddr = b58encode(str(binAddr).encode('utf-8'))
    return walletAddr.decode('ascii')
