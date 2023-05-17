import hashlib
import uuid
import time
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import rsa

class Blockchain:
    def __init__(self, currentNodeUrl,stakeNode):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        self.chain = []
        self.pendingTransactions = []
        self.nodeUrl = currentNodeUrl
        self.networkNodes = []
        self.stake = stakeNode
        self.privateKey=private_key
        self.publicKey = public_key
        self.createNewBlock(100, '0', '0','Hritik','Ranjan')

    def createNewBlock(self, nonce, previousBlockHash, hash,signature,minerPublicKey):
        newBlock = {
            'index': len(self.chain) + 1,
            'timestamp': int(time.time() * 1000),
            'transactions': self.pendingTransactions,
            'nonce': nonce,
            'hash': hash,
            'signature':signature,
            'minerPublicKey':minerPublicKey,
            'previousBlockHash': previousBlockHash
        }
        self.pendingTransactions = []
        self.chain.append(newBlock)
        return newBlock

    def getLastBlock(self):
        return self.chain[-1]

    def createNewTransaction(self, amount, sender, recipient):
        newTransaction = {
            'amount': amount,
            'sender': sender,
            'recipient': recipient,
            'transactionId': str(uuid.uuid4().hex).replace('-', '')
        }
        # self.pendingTransactions.append(newTransaction)
        # return self.getLastBlock()['index'] + 1
        return newTransaction

    def addTransactionToPendingTransactions(self, transactionObj):
        self.pendingTransactions.append(transactionObj)
        return self.getLastBlock()['index'] + 1

    def updateBalance(self,amount):
        self.stake = self.stake + amount
        return self.stake
    
    def updateStake(self,amount):
        self.stake = self.stake - amount
        return self.stake

    def hashBlock(self, previousBlockHash, currentBlockData, nonce):
        dataAsString = str(previousBlockHash) + str(nonce) + str(currentBlockData)
        hash = hashlib.sha256(dataAsString.encode()).hexdigest()
        return hash

    def nonceCalculation(self, previousBlockHash, currentBlockData, difficulty):
        k='0'
        nonce = 0
        hash = self.hashBlock(previousBlockHash, currentBlockData, nonce)
        while hash[:difficulty] != k*difficulty:
            nonce += 1
            hash = self.hashBlock(previousBlockHash, currentBlockData, nonce)

        return nonce
