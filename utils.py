import hashlib
import json

def sha256(message):
    return hashlib.sha256(message.encode('ascii')).hexdigest()

def block_hash(message):
    # Recalculate hash using SHA256
    return sha256(message)

def mine(message, difficulty=1):
    assert difficulty >=1
    i=0
    prefix = '1' * difficulty
    while True:
        nonce = str(i)
        digest = block_hash(message+nonce)
        if digest.startswith(prefix):
            return nonce, i
        i += 1

# Definition of computeBalance (moved from main.py)
def computeBalance(wallet_address, transactions_list):
    balance = 0
    for t in transactions_list:
        for txin in t.inputs:
            # parent_output should be a TransactionOutput object
            if hasattr(txin, 'parent_output') and txin.parent_output.recipient == wallet_address:
                balance -= txin.parent_output.amount
        
        for txout in t.outputs:
            if txout.recipient == wallet_address:
                balance += txout.amount
    return balance
