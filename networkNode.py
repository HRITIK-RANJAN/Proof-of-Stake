from flask import Flask, jsonify, request
import sys
import requests
import uuid
from urllib.parse import urlparse
import random
from blockchain import Blockchain
import pickle
import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import rsa
from Crypto.PublicKey import RSA
import json


import argparse

parser = argparse.ArgumentParser(description='Blockchain Node')
parser.add_argument('-p', '--port', type=int, default=8000, help='port to listen on')
parser.add_argument('-s', '--stake', type=int, default=200, help='stake of node')
args = parser.parse_args()
port = args.port
stakes = args.stake

# Instantiate a Flask web app
app = Flask(__name__)
portp = port
stakeNode = stakes
currentNodeUrl="http://127.0.0.1:"+str(portp)
# Instantiate a Blockchain object
blockchain = Blockchain(currentNodeUrl,stakeNode)
# Generate a unique node address
nodeAddress = str(uuid.uuid1()).replace('-', '')

class Validator:
    def __init__(self, name, stake,privateKey,publicKey):
        self.name = name
        self.stake = stake
        self.privateKey = privateKey
        self.publicKey = publicKey
    
    def __repr__(self):
        return f"{self.name} ({self.stake} coins)"
    
class ChooseValidator:
    def __init__(self, validators):
        self.validators = validators
    
    def select_validator(self):
        total_stake = sum(v.stake for v in self.validators)
        r = random.uniform(0, total_stake)
        for v in self.validators:
            r -= v.stake
            if r <= 0:
                return v
        raise Exception("No validator selected")
        

# Route for the homepage
@app.route('/', methods=['GET'])
def home():
    return "Hello, Coding Python!"

# Route for the blockchain
@app.route('/blockchain', methods=['GET'])
def get_blockchain():
    
    # Serialize the public key to bytes
    public_key_bytes = blockchain.publicKey.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    # Convert the public key bytes to a base64-encoded string
    public_key_str = base64.b64encode(public_key_bytes).decode()

    # Serialize the private key to bytes
    private_key_bytes = blockchain.privateKey.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    # Convert the private key bytes to a base64-encoded string
    private_key_str = base64.b64encode(private_key_bytes).decode()

    response = {
        'chain': blockchain.chain,
        'length': len(blockchain.chain),
        'Network nodes': blockchain.networkNodes,
        'Current Node': blockchain.nodeUrl,
        'publicKey':public_key_str,
        'privateKey':private_key_str,
        'stake':blockchain.stake,
        'Pending Transactions': blockchain.pendingTransactions
    }
    return jsonify(response), 200

# Route for mining a new block
@app.route('/mine', methods=['GET'])
def get_mine():
    threshold=300
    # Get the last block in the chain
    lastBlock = blockchain.getLastBlock()
    previousBlockHash = lastBlock['hash']
    sender=blockchain.pendingTransactions[0]['sender']
    currentBlockData = {
       'transactions': blockchain.pendingTransactions,
       'index': lastBlock['index']+1
    }
    nonce = blockchain.nonceCalculation(previousBlockHash, currentBlockData,2)
    blockHash = blockchain.hashBlock( previousBlockHash, currentBlockData, nonce)

    requestPromises = []
    for networkNodeUrl in blockchain.networkNodes:
        requestOptions = {
            'url': networkNodeUrl + '/blockchain',
        }
        requestPromises.append(requests.get(**requestOptions))
    blockchainss = [response.json() for response in requestPromises]
    validators = []
    for blockchainn in blockchainss:
        node=blockchainn['Current Node']
        stake=blockchainn['stake']
        privateKey=blockchainn['privateKey']
        publicKey=blockchainn['publicKey']
        if stake>=threshold:
            validators.append(Validator(node,stake,privateKey,publicKey))
    blockchain1 = ChooseValidator(validators)
    validator = blockchain1.select_validator()
    print(f"Selected validator: {validator}")
    private_key=validator.privateKey
    public_key=validator.publicKey

    # Pickle the private key string
    pickled_key2 = json.dumps(private_key)
    # Unpickle the private key string
    unpickled_key_str = json.loads(pickled_key2)
    # Convert the unpickled private key string back to bytes
    unpickled_key_bytes = base64.b64decode(unpickled_key_str)
    # Deserialize the private key from bytes
    unpickled_private_key = serialization.load_pem_private_key(unpickled_key_bytes,password=None, backend=default_backend())

    message = memoryview(blockHash.encode('utf-8')).tobytes()
    signature = unpickled_private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    newBlock = blockchain.createNewBlock(nonce, previousBlockHash, blockHash,signature,public_key)
    typecastSignature =str(newBlock['signature'])
    newBlock['signature']=typecastSignature
    request_promises = []
    for network_node_url in blockchain.networkNodes:
        request_options = {
            "url": network_node_url + "/receive-new-block",
            "json": {"newBlock": newBlock},
        }
        request_promises.append(requests.post(**request_options))
    requestOptions={
        "url":str( blockchain.nodeUrl )+ "/transaction/broadcast",
        "json":{
            "amount": 15,
            "sender": sender,
            "recipient": validator.name,
        }}
    requests.post(**requestOptions)
    response = {"message": "New block mined successfully",
                 "block": newBlock}
    return jsonify(response)


@app.route('/receive-new-block', methods=['POST'])
def receive_new_block():
    newBlock = request.json['newBlock']
    last_block = blockchain.getLastBlock()
    correct_hash = last_block['hash'] == newBlock['previousBlockHash']
    correct_index = last_block['index'] + 1 == newBlock['index']
    if correct_hash and correct_index:
        blockchain.chain.append(newBlock)
        blockchain.pendingTransactions = []
        response = {
            "note": "New Block received and accepted",
            "newBlock": newBlock
        }
    else:
        response = {
            "note": "New Block Rejected",
            "newBlock": newBlock
        }
    return jsonify(response)

@app.route('/updateBalance', methods=['POST'])
def updateBalance():
    amount=request.json['amount']
    blockchain.updateBalance(amount)
    response = {'note':'Stake balance updated Successfully'}
    return jsonify(response)

@app.route('/updateStake', methods=['POST'])
def updateStakes():
    amount=request.json['amount']
    blockchain.updateStake(amount)
    response = {'note':'Stake balance updated Successfully'}
    return jsonify(response)

@app.route('/addToPending', methods=['POST'])
def addToPending():
    transactionObj = request.json['transaction']
    blockchain.addTransactionToPendingTransactions(transactionObj)
    response = {'note':'Transaction added to pending transactions'}
    return jsonify(response)

@app.route('/transaction', methods=['POST'])
def add_transaction():
    sender = blockchain.nodeUrl
    recipient = request.json['recipient']
    amount = request.json['amount']
    requestOption_Sender = {
            'url': sender + '/blockchain',
        }
    response1=requests.get(**requestOption_Sender)
    sender_node=response1.json()
    senderStake= sender_node['stake']
    if not amount<=(senderStake-15): 
        response = {"Note":"Invalid Transaction due to insufficient tokens"}
    else:
        requestOptionRecipient = {
            'url': recipient + '/updateBalance',
            'json':{'amount':amount}
        }
        requests.post(**requestOptionRecipient)
        requestOptionSender = {
            'url': sender + '/updateStake',
            'json':{'amount':amount}
        }
        requests.post(**requestOptionSender)
        newTransaction = {
            'sender' : sender,
            'recipient':  recipient,
            'amount': amount
        }
        blockIndex = blockchain.getLastBlock()['index']+1
        # blockchain.addTransactionToPendingTransactions(newTransaction)
        transaction = blockchain.createNewTransaction(newTransaction['amount'],newTransaction['sender'],newTransaction['recipient'])
        ar=[sender,recipient]
        for each in ar:
            requestoptioN = {
            'url': each + '/addToPending',
            'json':{'transaction':transaction}
            }
            requests.post(**requestoptioN)
        # block_index = bitcoin.createNewTransaction(req.json['amount'], req.json['sender'], req.json['recipient'])
        response = {"note": f"Transaction will be added in block {blockIndex}."}
    return jsonify(response)


@app.route('/transaction/broadcast', methods=['POST'])
def broadcast_transaction():
    sender = request.json['sender']
    recipient = request.json['recipient']
    amount = request.json['amount']

    requestOption_Sender = {
            'url': sender + '/blockchain',
        }
    response1=requests.get(**requestOption_Sender)
    sender_node=response1.json()
    senderStake= sender_node['stake']
    if not amount<=(senderStake-15): 
        response = {"Note":"Invalid Transaction due to insufficient tokens"}
    else:
        requestOptionRecipient = {
            'url': recipient + '/updateBalance',
            'json':{'amount':amount}
        }
        requests.post(**requestOptionRecipient)
        requestOptionSender = {
            'url': sender + '/updateStake',
            'json':{'amount':amount}
        }
        requests.post(**requestOptionSender)
        blockIndex = blockchain.getLastBlock()['index']+1
        transaction = blockchain.createNewTransaction(amount, sender, recipient)
        print(transaction)
        requestoptioN = {
        'url': currentNodeUrl + '/blockchain',
        }
        responses = requests.get(**requestoptioN)
        responses1=responses.json()
        currentNodePendingTransaction= responses1['Pending Transactions']
        if transaction not in currentNodePendingTransaction:
            requestoptioN1 = {
            'url': currentNodeUrl + '/addToPending',
            'json':{'transaction':transaction}
            }
            requests.post(**requestoptioN1)
        request_promises = []
        for network_node_url in blockchain.networkNodes:
            request_options = {
                "url": f"{network_node_url}/addToPending",
                "json": {'transaction':transaction}
            }
            request_promises.append(requests.post(**request_options))
        response = {"note":f"Transaction created and broadcasted successfully to block {blockIndex}."}
    return jsonify(response)

@app.route('/register-and-broadcast-node', methods=['POST'])
def register_and_broadcast_node():
    all_network_nodes = request.json['allNetworkNodes']
    if all_network_nodes is None:
        return "Error: Please supply a valid list of nodes", 400
    for new_node_url in all_network_nodes:
        if new_node_url not in blockchain.networkNodes:
            blockchain.networkNodes.append(new_node_url)
        reg_node_promises = []
        for network_node_url in blockchain.networkNodes:
            if network_node_url != new_node_url:
                request_options = {
                    "url": str(network_node_url)+"/register-node",
                    "json": {"newNodeUrl": new_node_url}
                }
                reg_node_promises.append(requests.post(**request_options))
        bulk_register_options = {
            "url": str(new_node_url)+"/register-nodes-bulk",
            "json": {"allNetworkNodes": [*blockchain.networkNodes, blockchain.nodeUrl]}
        }
        requests.post(**bulk_register_options)
    response = {"note": "New nodes registered with network successfully"}
    return jsonify(response)

# Route for registering a new node
@app.route('/register-node', methods=['POST'])
def register_node():
    newNodeUrl = request.json['newNodeUrl']
    nodeNotAlreadyPresent = newNodeUrl not in blockchain.networkNodes
    notCurrentNode = blockchain.nodeUrl != newNodeUrl
    if nodeNotAlreadyPresent and notCurrentNode:
        blockchain.networkNodes.append(newNodeUrl)

    response = {'note': 'New node registered successfully'}
    return jsonify(response)

@app.route('/register-nodes-bulk', methods=['POST'])
def register_nodes_bulk():
    all_network_nodes = request.json['allNetworkNodes']
    if all_network_nodes is None:
        return "Error: Please supply a valid list of nodes", 400

    for network_node_url in all_network_nodes:
        if network_node_url != blockchain.nodeUrl:
            if network_node_url not in blockchain.networkNodes:
                blockchain.networkNodes.append(network_node_url)
    response = {
        'note': 'Bulk registration successful.'
    }
    return jsonify(response), 201

@app.route('/consensus', methods=['GET'])
def consensus():
    requestPromises = []
    for networkNodeUrl in blockchain.networkNodes:
        requestOptions = {
            'url': networkNodeUrl + '/blockchain',
        }
        requestPromises.append(requests.get(**requestOptions))

    blockchains = [response.json() for response in requestPromises]
    currentChainLength = len(blockchain.chain)
    maxChainLength = 0
    maxstake=0
    newLongestChain = None
    newPendingTransactions = None
    allchain = []
    for blockchainn in blockchains:
            if maxChainLength <= blockchainn['length'] :
                allchain.append((blockchainn['length'],blockchainn['stake'],blockchainn['chain']))
                maxChainLength=blockchainn['length']
            # maxChainLength = len(blockchainn['chain'])
            # newLongestChain = blockchainn['chain']
            # newPendingTransactions = blockchainn['Pending Transactions']
    
    for i in allchain:
        if(i[0]==maxChainLength and maxstake<=i[1]):
            newLongestChain =i[2]
            maxstake=i[1]

    if newLongestChain is None or (newLongestChain ==blockchain.chain):
        response = {'note': 'Current chain has not been replaced', 'chain': blockchain.chain}
    else:
        blockchain.chain = newLongestChain
        blockchain.pendingTransactions = newPendingTransactions
        response = {'note': 'This chain has been replaced', 'chain': blockchain.chain}

    return jsonify(response)

if __name__ == '__main__':
    app.run(host='127.0.0.1',port=port)