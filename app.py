```python
import hashlib
import json
import time
import uuid
from flask import Flask, jsonify, request, render_template
from flask_socketio import SocketIO, emit
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import binascii
import logging
import os

# --- Configuration ---
MINING_DIFFICULTY = 2
BLOCK_REWARD = 25.0
MIN_TRANSACTION_FEE = 0.1 

# --- Logging Setup ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# --- Utility Functions (from utils.py) ---
def sha256(message):
    return hashlib.sha256(message.encode('ascii')).hexdigest()

def block_hash_func(block_data): # Renamed to avoid conflict with Block.hash method
    """Hashes the block data (excluding its own hash)."""
    # Ensure consistent serialization for hashing
    block_string = json.dumps(block_data, sort_keys=True).encode()
    return hashlib.sha256(block_string).hexdigest()

def mine_util(message, difficulty=DIFFICULTY):
    assert difficulty >= 1
    prefix = '0' * difficulty 
    for i in range(1000000):  # Increased range for better chance of finding a hash
        nonce = str(i)
        digest = sha256(message + nonce)
        if digest.startswith(prefix):
            return nonce, digest
    return None, None # Indicate failure if no nonce is found within the range

# --- Wallet Class ---
class Wallet:
    def __init__(self, private_key_pem=None):
        if private_key_pem:
            try:
                if isinstance(private_key_pem, bytes):
                    private_key_pem = private_key_pem.decode('utf-8')
                # Ensure PEM format markers are present
                if not private_key_pem.startswith('-----BEGIN RSA PRIVATE KEY-----'):
                    from Crypto.IO import PEM
                    # Try decoding if it looks like hex, otherwise assume base64
                    try:
                        key_data = binascii.unhexlify(private_key_pem)
                    except binascii.Error:
                        key_data = private_key_pem.encode('ascii') # Fallback if not hex
                    
                    pem_data = "-----BEGIN RSA PRIVATE KEY-----\n" + \
                               binascii.b2a_base64(key_data).decode('ascii').strip().replace('\n', '') + \
                               "\n-----END RSA PRIVATE KEY-----"
                    self._private_key = RSA.import_key(pem_data)
                else:
                    self._private_key = RSA.import_key(private_key_pem)
            except Exception as e:
                raise ValueError(f"Invalid private key format or content: {e}")
        else:
            random_gen = Crypto.Random.new().read
            self._private_key = RSA.generate(1024, random_gen)
        self._public_key = self._private_key.publickey()
        self._signer = pkcs1_15.new(self._private_key)

    @property
    def address(self):
        return binascii.hexlify(self._public_key.export_key(format='DER')).decode('ascii')

    def sign(self, message):
        h = SHA256.new(message.encode('utf-8'))
        signature = self._signer.sign(h)
        return binascii.hexlify(signature).decode('ascii')

    def export_private_key(self):
        return self._private_key.export_key().decode('ascii')

    @staticmethod
    def verify_signature(public_key_hex, message, signature):
        try:
            public_key_der = binascii.unhexlify(public_key_hex)
            key = RSA.import_key(public_key_der)
            h = SHA256.new(message.encode('utf-8'))
            verifier = pkcs1_15.new(key)
            return verifier.verify(h, binascii.unhexlify(signature))
        except (ValueError, TypeError) as e:
            app.logger.error(f"Signature verification error: {e}")
            return False

# --- Transaction Classes ---
class TransactionOutput:
    def __init__(self, recipient_address, amount):
        self.recipient = recipient_address
        self.amount = float(amount)

    def to_dict(self):
        return {'recipient_address': self.recipient, 'amount': self.amount}

    def __eq__(self, other):
        if not isinstance(other, TransactionOutput):
            return NotImplemented
        return self.recipient == other.recipient and self.amount == other.amount
    
    def __hash__(self):
        return hash((self.recipient, self.amount))

class TransactionInput:
    def __init__(self, transaction, output_index):
        self.transaction = transaction  # This is the actual parent Transaction object
        self.output_index = output_index
        if not hasattr(transaction, 'outputs') or not isinstance(transaction.outputs, list):
            raise ValueError("TransactionInput: 'transaction' object is malformed or missing 'outputs'.")
        if not (0 <= self.output_index < len(transaction.outputs)):
            raise ValueError(f"TransactionInput: Output index {output_index} is out of range for transaction with {len(transaction.outputs)} outputs.")
        self.transaction_hash = transaction.hash()
        self.transaction_output = transaction.outputs[output_index]

    def to_dict(self): # For signing
        return {
            'transaction_hash': self.transaction_hash,
            'output_index': self.output_index
        }
    
    def to_display_dict(self): # For API responses
        return {
            'transaction_hash': self.transaction_hash,
            'output_index': self.output_index,
            'address': self.transaction_output.recipient if self.transaction_output else None,
            'amount': self.transaction_output.amount if self.transaction_output else None
        }

    def __eq__(self, other):
        if not isinstance(other, TransactionInput):
            return NotImplemented
        return (self.transaction_hash == other.transaction_hash and
                self.output_index == other.output_index)

    def __hash__(self):
        return hash((self.transaction_hash, self.output_index))

class Transaction:
    def __init__(self, sender_address, recipient_address, amount, inputs, outputs, timestamp=None, signature=None, tx_id=None):
        self.sender_address = sender_address
        self.recipient_address = recipient_address 
        self.amount = float(amount) 
        self.inputs = inputs 
        self.outputs = outputs 
        self.timestamp = timestamp if timestamp is not None else time.time()
        self.signature = signature
        self.fee = self._calculate_fee() if inputs else 0.0
        self._tx_id_cached = tx_id

    def _calculate_fee(self):
        input_total = sum(inp.transaction_output.amount for inp in self.inputs if inp.transaction_output)
        output_total = sum(out.amount for out in self.outputs)
        if input_total < output_total:
            raise ValueError(f"Transaction outputs ({output_total}) exceed inputs ({input_total}).")
        return round(input_total - output_total, 8)

    def _data_to_sign(self):
        sorted_inputs = sorted([inp.to_dict() for inp in self.inputs], key=lambda x: (x['transaction_hash'], x['output_index']))
        sorted_outputs = sorted([out.to_dict() for out in self.outputs], key=lambda x: (x['recipient_address'], x['amount']))
        
        return {
            "sender_address": self.sender_address,
            "recipient_address": self.recipient_address,
            "amount": self.amount,
            "inputs": sorted_inputs,
            "outputs": sorted_outputs,
            "timestamp": self.timestamp,
            "fee": self.fee
        }

    def to_dict(self, include_signature=True):
        data = self._data_to_sign() 
        data["inputs"] = [inp.to_display_dict() for inp in self.inputs]
        if include_signature and self.signature:
            data["signature"] = self.signature
        data["tx_id"] = self.hash()
        return data

    def hash(self):
        if not hasattr(self, '_tx_id_cached') or self._tx_id_cached is None:
            self._tx_id_cached = sha256(json.dumps(self._data_to_sign(), sort_keys=True))
        return self._tx_id_cached
    
    def sign(self, private_key_pem):
        signer_wallet = WalletClass(private_key_pem=private_key_pem)
        if signer_wallet.address != self.sender_address:
            raise ValueError("Private key does not correspond to the sender_address.")
        message_to_sign = json.dumps(self._data_to_sign(), sort_keys=True)
        self.signature = signer_wallet.sign(message_to_sign)

    def verify_signature(self):
        if self.signature is None:
            return False
        message_to_verify = json.dumps(self._data_to_sign(), sort_keys=True)
        return WalletClass.verify_signature(self.sender_address, message_to_verify, self.signature)

class GenesisTransaction(Transaction):
    def __init__(self, recipient_address, amount=BLOCK_REWARD):
        super().__init__(
            sender_address="0", 
            recipient_address=recipient_address,
            amount=amount,
            inputs=[],
            outputs=[TransactionOutput(recipient_address, amount)],
            signature="genesis" 
        )
        self.fee = 0.0 
        self._tx_id_cached = self._calculate_hash()

    def _data_to_sign(self): 
        return {
            "outputs": [out.to_dict() for out in self.outputs],
            "timestamp": self.timestamp,
            "fee": self.fee,
            "recipient_address": self.recipient_address, 
            "amount": self.amount,
            "message": "Genesis Block Transaction" 
        }
    
    def verify_signature(self):
        return self.signature == "genesis"

def verifyTransaction(transaction, current_blockchain, current_mempool):
    if not isinstance(transaction, Transaction):
        logging.error(f"Verification failed: Object is not a Transaction instance: {type(transaction)}")
        return False

    if not transaction.verify_signature():
        logging.error(f"Invalid signature for transaction {transaction.hash()}")
        return False

    if isinstance(transaction, GenesisTransaction):
        return True

    if not transaction.inputs:
        logging.error(f"Transaction {transaction.hash()} has no inputs.")
        return False

    spent_in_this_tx = set()
    total_input_value = 0.0

    spent_outputs_on_chain = set()
    for block in current_blockchain:
        for tx_in_block in block.transactions:
            if not isinstance(tx_in_block, GenesisTransaction):
                for inp in tx_in_block.inputs:
                    spent_outputs_on_chain.add((inp.transaction_hash, inp.output_index))
    
    spent_outputs_in_mempool = set()
    for mem_tx in current_mempool:
        if mem_tx.hash() != transaction.hash(): 
            if not isinstance(mem_tx, GenesisTransaction):
                for inp in mem_tx.inputs:
                    spent_outputs_in_mempool.add((inp.transaction_hash, inp.output_index))

    for tx_input in transaction.inputs:
        utxo_id = (tx_input.transaction_hash, tx_input.output_index)
        
        if utxo_id in spent_in_this_tx:
            logging.error(f"Transaction {transaction.hash()} attempts to spend the same UTXO twice: {utxo_id}")
            return False
        spent_in_this_tx.add(utxo_id)

        if utxo_id in spent_outputs_on_chain:
            logging.error(f"Input UTXO {utxo_id} for tx {transaction.hash()} is already spent in blockchain.")
            return False
        if utxo_id in spent_outputs_in_mempool:
            logging.error(f"Input UTXO {utxo_id} for tx {transaction.hash()} is already spent in mempool by another transaction.")
            return False

        if tx_input.transaction_output is None:
            logging.error(f"Input UTXO {utxo_id} for tx {transaction.hash()} does not have associated output data.")
            return False
        
        if tx_input.transaction_output.recipient != transaction.sender_address:
            logging.error(f"Input UTXO {utxo_id} (recipient: {tx_input.transaction_output.recipient}) does not belong to sender {transaction.sender_address} for tx {transaction.hash()}")
            return False
        total_input_value += tx_input.transaction_output.amount
            
    total_output_value = sum(out.amount for out in transaction.outputs)
    
    calculated_fee = round(total_input_value - total_output_value, 8)
    if abs(transaction.fee - calculated_fee) > 1e-9: 
        logging.error(f"Transaction {transaction.hash()} fee mismatch. Stored: {transaction.fee}, Calculated: {calculated_fee}, Input: {total_input_value}, Output: {total_output_value}")
        return False
    if transaction.fee < 0:
        logging.error(f"Transaction {transaction.hash()} has a negative fee: {transaction.fee}")
        return False
        
    return True

class Block:
    def __init__(self, transactions, ancestor, miner_address, skip_verify=False, current_blockchain_for_validation=None, current_mempool_for_validation=None):
        self.timestamp = time.time()
        self.transactions = [] 
        self.miner = miner_address
        self.previous_hash = ancestor.hash() if ancestor else "0" * 64
        
        total_fees = sum(tx.fee for tx in transactions if not isinstance(tx, GenesisTransaction))
        coinbase_amount = BLOCK_REWARD + total_fees
        
        coinbase_tx = GenesisTransaction(recipient_address=miner_address, amount=coinbase_amount)
        self.transactions.append(coinbase_tx)

        for tx in transactions:
            if not skip_verify:
                blockchain_for_val = current_blockchain_for_validation if current_blockchain_for_validation is not None else blockchain
                mempool_for_val = [m_tx for m_tx in (current_mempool_for_validation if current_mempool_for_validation is not None else mempool) if m_tx.hash() != tx.hash()]
                
                if not verifyTransaction(tx, blockchain_for_val, mempool_for_val):
                    raise ValueError(f"Invalid transaction in block: {tx.hash()}")
            self.transactions.append(tx)
        
        self.nonce, self._hash = self._mine_block() 
        if self.nonce is None:
            raise Exception("Mining failed for block.")

    def _get_block_data_for_hashing(self):
        transactions_for_hashing = [tx.to_dict(include_signature=True) for tx in self.transactions]
        block_data = {
            "timestamp": self.timestamp,
            "transactions": transactions_for_hashing,
            "previous_hash": self.previous_hash,
            "miner": self.miner
        }
        return json.dumps(block_data, sort_keys=True)

    def _mine_block(self):
        block_data_str = self._get_block_data_for_hashing()
        nonce, hash_result = mine_util(block_data_str, DIFFICULTY) 
        if nonce is None:
            raise Exception(f"Mining timed out. Target: {'0'*DIFFICULTY}")
        return str(nonce), hash_result

    def hash(self):
        if not hasattr(self, '_hash') or self._hash is None:
            block_data_str = self._get_block_data_for_hashing()
            self._hash = sha256(block_data_str + str(self.nonce))
        return self._hash

    def to_dict(self, include_hash=True):
        return {
            "timestamp": self.timestamp,
            "transactions": [tx.to_dict() for tx in self.transactions],
            "previous_hash": self.previous_hash,
            "nonce": self.nonce,
            "hash": self.hash(), 
            "miner": self.miner
        }

class GenesisBlock(Block):       
    def __init__(self, miner_address):
        super().__init__(transactions=[], ancestor=None, miner_address=miner_address, skip_verify=True, current_blockchain=[], current_mempool=[])
        
    def to_dict(self, include_hash=True):
        d = super().to_dict(include_hash=include_hash) 
        d["genesis_block"] = True 
        return d

def verify_block_chain(chain_to_verify):
    global blockchain, mempool 
    if not chain_to_verify:
        return True 
    
    genesis = chain_to_verify[0]
    if not isinstance(genesis, GenesisBlock):
        app.logger.error("Blockchain does not start with a GenesisBlock.")
        return False
    if genesis.previous_hash != "0" * 64:
        app.logger.error("Genesis block's previous_hash is not all zeros.")
        return False
    
    target_prefix = '0' * DIFFICULTY
    genesis_data_for_hash = genesis._get_block_data_for_hashing()
    calculated_genesis_hash = sha256(genesis_data_for_hash + genesis.nonce)
    
    if not calculated_genesis_hash.startswith(target_prefix):
        app.logger.error(f"Genesis block PoW invalid. Hash: {calculated_genesis_hash}")
        return False
    if calculated_genesis_hash != genesis.hash:
         app.logger.error(f"Genesis block hash mismatch. Stored: {genesis.hash}, Calculated: {calculated_genesis_hash}")
         return False

    temp_blockchain_for_verification = [genesis] 
    for i in range(1, len(chain_to_verify)):
        current_block = chain_to_verify[i]
        previous_block = chain_to_verify[i-1]

        if current_block.previous_hash != previous_block.hash():
            app.logger.error(f"Block {i}: Previous hash mismatch. Expected {previous_block.hash()}, got {current_block.previous_hash}")
            return False

        current_block_data_for_hash = current_block._get_block_data_for_hashing()
        block_header_string_for_verification = current_block_data_for_hash + current_block.nonce
        calculated_hash = sha256(block_header_string_for_verification)
        
        if not calculated_hash.startswith(target_prefix):
            app.logger.error(f"Block {i} (hash: {current_block.hash}): PoW invalid. Hash {calculated_hash} does not start with '{target_prefix}'.")
            return False
        if calculated_hash != current_block.hash:
            app.logger.error(f"Block {i} ({current_block.hash}): Hash mismatch. Stored: {current_block.hash}, Calculated: {calculated_hash}")
            return False
            
        coinbase_tx = current_block.transactions[0]
        if not isinstance(coinbase_tx, GenesisTransaction): 
            app.logger.error(f"Block {i}: First transaction is not a GenesisTransaction (coinbase).")
            return False
        if len(coinbase_tx.inputs) != 0:
            app.logger.error(f"Block {i}: Coinbase transaction has inputs.")
            return False
        if len(coinbase_tx.outputs) != 1:
            app.logger.error(f"Block {i}: Coinbase transaction does not have exactly one output.")
            return False
        
        expected_reward = BLOCK_REWARD + sum(tx.fee for tx in current_block.transactions[1:])
        if abs(coinbase_tx.outputs[0].amount - expected_reward) > 1e-9: 
            app.logger.error(f"Block {i}: Coinbase transaction amount is incorrect. Expected {expected_reward}, got {coinbase_tx.outputs[0].amount}")
            return False
        if coinbase_tx.recipient_address != current_block.miner: 
            app.logger.error(f"Block {i}: Coinbase transaction recipient mismatch. Expected {current_block.miner}, got {coinbase_tx.recipient_address}")
            return False

        spent_in_this_block = set() 
        for tx_idx, tx in enumerate(current_block.transactions):
            if tx_idx == 0: 
                continue
            if isinstance(tx, GenesisTransaction): 
                app.logger.error(f"Block {i}: Non-coinbase GenesisTransaction found at index {tx_idx}.")
                return False
            
            if not verifyTransaction(tx, temp_blockchain_for_verification, []): 
                app.logger.error(f"Block {i}: Transaction {tx.hash()} is invalid.")
                return False
            
            for tx_input in tx.inputs:
                utxo_id = (tx_input.transaction_hash, tx_input.output_index)
                if utxo_id in spent_in_this_block:
                    app.logger.error(f"Block {i}: Double spend detected within the block for UTXO {utxo_id}.")
                    return False
                spent_in_this_block.add(utxo_id)
                
        temp_blockchain_for_verification.append(current_block)
        last_block = current_block
            
    return True

app = Flask(__name__)
socketio = SocketIO(app) # Initialize SocketIO

# Global variables
blockchain = []
mempool = []
wallets = {}
MINER_WALLET = None
alice_wallet_global = None # To store Alice's wallet object for easy access in tests
bob_wallet_global = None   # To store Bob's wallet object for easy access in tests

def initialize_blockchain_and_wallets():
    global MINER_WALLET, blockchain, wallets, mempool, alice_wallet_global, bob_wallet_global
    
    if blockchain: # Prevent re-initialization
        return

    satoshi_wallet = WalletClass()
    wallets[satoshi_wallet.address] = satoshi_wallet
    MINER_WALLET = satoshi_wallet
    app.logger.info(f"Satoshi (Miner) Wallet Address: {MINER_WALLET.address}")

    genesis_b = GenesisBlock(miner_address=MINER_WALLET.address)
    blockchain.append(genesis_b)
    app.logger.info(f"Genesis Block created: {genesis_b.hash}")

    alice_wallet_global = WalletClass()
    wallets[alice_wallet_global.address] = alice_wallet_global
    app.logger.info(f"Alice's Wallet Address: {alice_wallet_global.address}")
    
    bob_wallet_global = WalletClass()
    wallets[bob_wallet_global.address] = bob_wallet_global
    app.logger.info(f"Bob's Wallet Address: {bob_wallet_global.address}")

    # Pre-fund Alice
    satoshi_genesis_tx = genesis_b.transactions[0]
    amount_to_alice = 10.0
    
    if satoshi_genesis_tx.outputs[0].amount >= amount_to_alice + MIN_TRANSACTION_FEE:
        inputs = [TransactionInput(transaction=satoshi_genesis_tx, output_index=0)]
        
        outputs = [TransactionOutput(recipient_address=alice_wallet_global.address, amount=amount_to_alice)]
        change_to_satoshi = satoshi_genesis_tx.outputs[0].amount - amount_to_alice - MIN_TRANSACTION_FEE
        if change_to_satoshi > 1e-8:
            outputs.append(TransactionOutput(recipient_address=satoshi_wallet.address, amount=round(change_to_satoshi, 8)))

        try:
            initial_transaction = Transaction(
                sender_address=satoshi_wallet.address,
                recipient_address=alice_wallet_global.address,
                amount=amount_to_alice,
                inputs=inputs,
                outputs=outputs
            )
            initial_transaction.sign(satoshi_wallet.export_private_key())
            
            if verifyTransaction(initial_transaction, blockchain, []):
                mempool.append(initial_transaction)
                app.logger.info(f"Initial transaction (Satoshi to Alice for {amount_to_alice}) added to mempool.")

                block1 = Block(
                    transactions=list(mempool), 
                    ancestor=blockchain[-1], 
                    miner_address=MINER_WALLET.address,
                    current_blockchain=blockchain,
                    current_mempool=[]
                )
                blockchain.append(block1)
                mempool.clear()
                app.logger.info(f"Block 1 mined by {MINER_WALLET.address}, hash: {block1.hash}")
            else:
                app.logger.error(f"Initial transaction from Satoshi to Alice failed verification.")
        except Exception as e:
            app.logger.error(f"Error creating initial transaction: {e}", exc_info=True)
    else:
        app.logger.error(f"Satoshi's initial output not enough for transfer.")
        
    app.logger.info("Blockchain initialized.")

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/get_addresses', methods=['GET'])
def get_addresses_api():
    global MINER_WALLET, alice_wallet_global, bob_wallet_global
    return jsonify({
        "satoshi_address": MINER_WALLET.address if MINER_WALLET else None,
        "alice_address": alice_wallet_global.address if alice_wallet_global else None,
        "bob_address": bob_wallet_global.address if bob_wallet_global else None
    })

@app.route('/api/wallet/create', methods=['POST'])
def create_wallet_api():
    new_wallet = WalletClass()
    wallets[new_wallet.address] = new_wallet
    app.logger.info(f"Created new wallet: {new_wallet.address}")
    return jsonify({
        'address': new_wallet.address,
        'private_key': new_wallet.export_private_key(),
        'public_key': new_wallet.address 
    }), 201

@app.route('/api/wallet/<address>/balance', methods=['GET'])
def get_balance_api(address):
    global blockchain, mempool, MINER_WALLET
    
    if not blockchain:
        return jsonify({'error': 'Blockchain not initialized or empty'}), 500
        
    balance = compute_balance(address, blockchain, mempool, GenesisTransaction) # Pass GenesisTransaction class
    
    # Debugging for Satoshi's address (MINER_WALLET)
    if request.args.get('debug') == 'true' and MINER_WALLET and address == MINER_WALLET.address:
        debug_log = []
        logged_balance = 0.0 
        
        spent_outputs_on_chain_debug = set()
        for block_item in blockchain:
            for tx in block_item.transactions:
                if not isinstance(tx, GenesisTransaction):
                    for tx_input in tx.inputs:
                        spent_outputs_on_chain_debug.add((tx_input.transaction_hash, tx_input.output_index))
        
        spent_outputs_in_mempool_debug = set()
        for tx in mempool:
            if not isinstance(tx, GenesisTransaction):
                for tx_input in tx.inputs:
                    spent_outputs_in_mempool_debug.add((tx_input.transaction_hash, tx_input.output_index))

        # Process blockchain transactions for debug log
        for block_idx, block in enumerate(blockchain):
            for tx_idx_in_block, t in enumerate(block.transactions):
                tx_hash = t.hash()
                tx_info = {
                    "block_index": block_idx,
                    "tx_index_in_block": tx_idx_in_block,
                    "tx_hash": tx_hash,
                    "tx_type": type(t).__name__,
                    "inputs_effects": [],
                    "outputs_effects": [],
                    "balance_change_from_tx": 0.0,
                    "source": "blockchain"
                }
                current_tx_balance_change = 0.0

                if not isinstance(t, GenesisTransaction):
                    for i_idx, txin in enumerate(t.inputs):
                        parent_output = txin.transaction_output 
                        effect = ""
                        if parent_output.recipient == address:
                            current_tx_balance_change -= parent_output.amount
                            effect = f"Subtracted {parent_output.amount}"
                        tx_info["inputs_effects"].append({
                            "input_index": i_idx,
                            "parent_tx_hash": txin.transaction_hash,
                            "parent_output_index": txin.output_index,
                            "parent_output_recipient": parent_output.recipient,
                            "parent_output_amount": parent_output.amount,
                            "match_address": (parent_output.recipient == address),
                            "effect_on_balance": effect
                        })
                
                for o_idx, txout in enumerate(t.outputs):
                    effect = ""
                    is_spent = (tx_hash, o_idx) in spent_outputs_on_chain_debug or \
                               (tx_hash, o_idx) in spent_outputs_in_mempool_debug
                    
                    if txout.recipient == address:
                        if not is_spent:
                            current_tx_balance_change += txout.amount
                            effect = f"Added {txout.amount}"
                        else:
                            effect = f"Received {txout.amount} (spent)"
                    tx_info["outputs_effect"].append({
                        "output_index": o_idx,
                        "recipient": txout.recipient,
                        "amount": txout.amount,
                        "match_address": (txout.recipient == address),
                        "is_spent": is_spent,
                        "effect_on_balance": effect
                    })
                
                tx_info["balance_change_from_tx"] = current_tx_balance_change
                logged_balance += current_tx_balance_change
                tx_info["cumulative_balance_after_tx"] = logged_balance
                debug_log.append(tx_info)

        # Debugging for Mempool transactions (affecting potential balance)
        mempool_balance_adjustment = 0.0
        for t_idx, t in enumerate(mempool):
            tx_info = {
                "tx_index_in_mempool": t_idx,
                "tx_hash": t.hash(),
                "tx_type": type(t).__name__,
                "inputs_effects": [],
                "outputs_effects": [],
                "balance_change_from_tx": 0.0,
                "source": "mempool (potential)"
            }
            tx_balance_change_for_this_tx = 0.0
            if not isinstance(t, GenesisTransaction):
                if t.sender_address == address:
                    for inp in t.inputs:
                        # Check if this input refers to a UTXO that was part of the confirmed balance
                        if (inp.transaction_hash, inp.output_index) in utxos: # utxos here should be from find_utxos_for_address
                             tx_balance_change_for_this_tx -= inp.transaction_output.amount
                        tx_info["inputs_effects"].append({
                            "from_tx": inp.transaction_hash,
                            "output_index": inp.output_index,
                            "amount": inp.transaction_output.amount,
                            "effect": f"Spending {inp.transaction_output.amount} (from mempool tx)"
                        })
            for txout in t.outputs:
                if txout.recipient == address:
                    tx_balance_change_for_this_tx += txout.amount
                    tx_info["outputs_effect"].append({
                        "recipient": txout.recipient,
                        "amount": txout.amount,
                        "effect": f"Receiving {txout.amount} (in mempool)"
                    })
            
            tx_info["balance_change_from_tx"] = tx_balance_change_for_this_tx
            # This logged_balance is for the debug trace, showing cumulative effect including mempool
            logged_balance += tx_balance_change_for_this_tx 
            tx_info["cumulative_balance_after_tx"] = logged_balance
            debug_log.append(tx_info)
            
        return jsonify({
            'address': address, 
            'balance': balance, 
            'debug_calculated_balance': logged_balance, # Balance from this detailed trace
            'debug_trace': debug_log
        })

    return jsonify({'address': address, 'balance': balance})

@app.route('/api/blockchain/blocks', methods=['GET'])
def get_blocks():
    return jsonify({'blocks': [block.to_dict(include_hash=True) for block in blockchain]})

@app.route('/api/mempool', methods=['GET'])
def get_mempool():
    return jsonify([tx.to_dict() for tx in mempool])

@app.route('/api/transaction/new', methods=['POST'])
def new_transaction_api():
    global mempool, blockchain, wallets
    values = request.get_json()
    if not values:
        return jsonify({'message': 'No data provided'}), 400
    required = ['sender_address', 'recipient_address', 'amount', 'private_key']
    if not all(k in values for k in required):
        return jsonify({'message': f'Missing values. Required fields are: {", ".join(required)}'}), 400

    sender_address = values['sender_address']
    recipient_address = values['recipient_address']
    try:
        amount = float(values['amount'])
        if amount <= 0:
            return jsonify({'message': 'Amount must be positive.'}), 400
    except ValueError:
        return jsonify({'message': 'Invalid amount format.'}), 400
    private_key_pem = values['private_key']

    if sender_address not in wallets:
        return jsonify({'message': f'Sender wallet {sender_address} not found on this server.'}), 400
    
    sender_wallet = wallets[sender_address]

    try:
        temp_wallet_for_check = WalletClass(private_key_pem=private_key_pem)
        if temp_wallet_for_check.address != sender_wallet.address:
             return jsonify({'message': 'Private key does not match sender address.'}), 403
    except ValueError as e:
        return jsonify({'message': f'Invalid private key format: {str(e)}'}), 400

    # Find UTXOs for the sender
    available_utxos = find_utxos_for_address(sender_address)
    
    inputs = []
    input_sum = 0.0
    
    required_total_for_tx = amount + MIN_TRANSACTION_FEE
    
    available_utxos.sort(key=lambda x: x['amount']) # Using smaller UTXOs first
    
    for utxo_data in available_utxos:
        # The 'transaction' key in utxo_data is the parent Transaction object.
        inputs.append(TransactionInput(transaction=utxo_data['transaction'], output_index=utxo_data['output_index']))
        input_sum += utxo_data['amount']
        if input_sum >= required_total_for_tx:
            break
            
    if input_sum < required_total_for_tx:
        return jsonify({'message': f'Insufficient funds. Available: {input_sum}, Required (incl. fee {MIN_TRANSACTION_FEE}): {required_total_for_tx}'}), 400

    outputs = [TransactionOutput(recipient_address, amount)]
    
    change = input_sum - amount - MIN_TRANSACTION_FEE
    if change > 1e-8: 
        outputs.append(TransactionOutput(sender_address, round(change, 8)))

    try:
        transaction = Transaction(
            sender_address=sender_wallet.address,
            recipient_address=recipient_address,
            amount=amount,
            inputs=inputs,
            outputs=outputs
        )
        transaction.sign(private_key_pem)
        
        if not verifyTransaction(transaction, blockchain, mempool):
            # The verifyTransaction function logs details, so we can return a generic error.
            return jsonify({'message': 'Transaction verification failed. Check server logs for details.'}), 400
        
        mempool.append(transaction)
        socketio.emit('new_transaction', transaction.to_dict()) # Emit new transaction
        # Emit balance updates for sender and receiver
        socketio.emit('balance_update', {'address': sender_address, 'balance': compute_balance(sender_address, blockchain, mempool, GenesisTransaction)})
        socketio.emit('balance_update', {'address': recipient_address, 'balance': compute_balance(recipient_address, blockchain, mempool, GenesisTransaction)})

        return jsonify({'message': 'Transaction created successfully and added to mempool.', 'transaction': transaction.to_dict()}), 201
    except ValueError as e: 
        return jsonify({'message': f'Error creating transaction: {str(e)}'}), 400
    except Exception as e:
        app.logger.error(f"Unexpected error in new_transaction: {e}", exc_info=True)
        return jsonify({'message': f'An unexpected error occurred: {str(e)}'}), 500


@app.route('/api/mine', methods=['GET'])
def mine_endpoint():
    global mempool, blockchain, MINER_WALLET

    if not blockchain:
        return jsonify({'message': 'Blockchain not initialized. Cannot mine.'}), 500
    
    if not MINER_WALLET:
        return jsonify({'message': 'Miner wallet not configured.'}), 500

    if not mempool:
        return jsonify({'message': 'No transactions to mine'}), 200

    transactions_to_mine = list(mempool) 
    valid_transactions_for_block = []
    
    current_blockchain_snapshot = list(blockchain) 
    
    temp_mempool_for_validation = list(mempool) 
    
    for tx in transactions_to_mine:
        mempool_without_current_tx = [m for m in temp_mempool_for_validation if m.hash() != tx.hash()]
        if verifyTransaction(tx, current_blockchain_snapshot, mempool_without_current_tx):
            valid_transactions_for_block.append(tx)
        else:
            app.logger.warning(f"Transaction {tx.hash()} from mempool failed verification and will be removed.")
            if tx in mempool: 
                mempool.remove(tx)

    if not valid_transactions_for_block:
        return jsonify({'message': 'No valid transactions in mempool to mine after verification.'}), 400

    last_block = blockchain[-1]
    
    try:
        new_block = Block(
            transactions=valid_transactions_for_block, 
            ancestor=last_block, 
            miner_address=MINER_WALLET.address,
            current_blockchain=blockchain, 
            current_mempool=[] 
        )
        blockchain.append(new_block)
        
        mempool_after_mining = [tx for tx in mempool if tx not in valid_transactions_for_block]
        mempool[:] = mempool_after_mining # Update global mempool
        
        socketio.emit('new_block', {'block': new_block.to_dict(include_hash=True), 'chain_length': len(blockchain)})
        socketio.emit('mempool_updated', {'mempool': [tx.to_dict() for tx in mempool]})

        # Update balances for involved parties
        affected_addresses = set()
        affected_addresses.add(MINER_WALLET.address) # Miner gets reward
        for tx in valid_transactions_for_block:
            affected_addresses.add(tx.sender_address)
            for output in tx.outputs:
                affected_addresses.add(output.recipient)
        
        for addr in affected_addresses:
            if addr == "0": continue # Skip genesis sender
            balance = compute_balance(addr, blockchain, mempool, GenesisTransaction)
            socketio.emit('balance_update', {'address': addr, 'balance': balance})
            
        return jsonify({
            'message': f'Block #{len(blockchain)-1} mined successfully!',
            'block': new_block.to_dict(include_hash=True)
        }), 201
        
    except Exception as e:
        app.logger.error(f"Error during block mining: {e}", exc_info=True)
        return jsonify({'message': f'An unexpected error occurred during mining: {str(e)}'}), 500

@app.route('/api/get_addresses', methods=['GET'])
def get_addresses_api():
    global wallets, MINER_WALLET, alice_wallet_global, bob_wallet_global
    satoshi_address = MINER_WALLET.address if MINER_WALLET else None
    alice_address = alice_wallet_global.address if alice_wallet_global else None
    bob_address = bob_wallet_global.address if bob_wallet_global else None
            
    return jsonify({
        "satoshi_address": satoshi_address,
        "alice_address": alice_address,
        "bob_address": bob_address
    })

# Initialize blockchain and wallets when the app starts
if __name__ == '__main__':
    if not blockchain: # Ensure initialization only happens once
        initialize_blockchain()
    socketio.run(app, host='0.0.0.0', port=5000, debug=True, use_reloader=False)

```

**File: `static/app.js`**
```javascript
document.addEventListener('DOMContentLoaded', () => {
    const newWalletAddressEl = document.getElementById('newWalletAddress');
    const newWalletPrivateKeyEl = document.getElementById('newWalletPrivateKey');
    const walletAddressEl = document.getElementById('walletAddressDisplay');
    const walletPrivateKeyInputEl = document.getElementById('senderPrivateKeyForTx');
    const walletBalanceEl = document.getElementById('walletBalance');
    const checkBalanceAddressInput = document.getElementById('myAddressInput');
    const balanceResultEl = document.getElementById('balanceResult'); // Ensure this ID exists in HTML

    const senderAddressInput = document.getElementById('senderAddress');
    const recipientAddressInput = document.getElementById('recipientAddress');
    const sendAmountInput = document.getElementById('sendAmount');
    const txStatusEl = document.getElementById('txStatus');

    const mempoolDataEl = document.getElementById('mempoolData');
    const blockchainDataEl = document.getElementById('blockchainData');
    const notificationsOutputEl = document.getElementById('notificationsOutput');

    const createWalletBtn = document.getElementById('createWalletBtn');
    const getWalletDataBtn = document.getElementById('getWalletDataBtn');
    const sendTransactionBtn = document.getElementById('sendTransactionBtn');
    const refreshMempoolBtn = document.getElementById('refreshMempoolBtn');
    const refreshBlockchainBtn = document.getElementById('refreshBlockchainBtn');
    const mineBlockBtn = document.getElementById('mineBlockBtn');

    const exportWalletBtn = document.getElementById('exportWalletBtn');
    const importWalletFileEl = document.getElementById('importWalletFile');
    const importWalletBtn = document.getElementById('importWalletBtn');

    let currentSatoshiAddress = '';
    let currentAliceAddress = '';
    let currentBobAddress = '';
    let currentWallet = null; // Store the current loaded/created wallet object

    // Initialize Socket.IO
    const socket = io.connect(location.protocol + '//' + document.domain + ':' + location.port);

    socket.on('connect', () => {
        logNotification('Connected to server via WebSocket.');
    });

    socket.on('disconnect', () => {
        logNotification('Disconnected from server.', 'error');
    });

    socket.on('new_transaction', (data) => {
        logNotification(`New transaction added to mempool: ${data.tx_id.substring(0,10)}...`);
        fetchMempool(); // Refresh mempool display
        // Update balances if relevant
        const currentDisplayedAddress = walletAddressEl.textContent;
        if (currentDisplayedAddress !== 'N/A') {
            if (data.sender_address === currentDisplayedAddress || data.outputs.some(out => out.recipient_address === currentDisplayedAddress)) {
                fetchBalance(currentDisplayedAddress, currentDisplayedAddress === currentSatoshiAddress);
            }
        }
    });

    socket.on('new_block', (data) => {
        logNotification(`New block mined: ${data.block.hash.substring(0,10)}... by ${data.block.miner.substring(0,10)}...`);
        fetchBlockchain(); // Refresh blockchain display
        fetchMempool();    // Refresh mempool (should be empty or updated)
        
        // Update balance for all known wallets if they were affected
        const affectedAddresses = new Set();
        affectedAddresses.add(data.block.miner); // Miner's address
        data.block.transactions.forEach(tx => {
            if (tx.sender_address && tx.sender_address !== "0") { // "0" for coinbase
                affectedAddresses.add(tx.sender_address);
            }
            tx.outputs.forEach(output => {
                affectedAddresses.add(output.recipient_address);
            });
        });

        affectedAddresses.forEach(addr => {
            fetchBalance(addr, addr === currentSatoshiAddress);
        });
        
        // Specifically update the current displayed wallet if it's not already covered
        const currentDisplayedAddress = walletAddressEl.textContent;
        if (currentDisplayedAddress && currentDisplayedAddress !== 'N/A' && !affectedAddresses.has(currentDisplayedAddress)) {
             fetchBalance(currentDisplayedAddress, currentDisplayedAddress === currentSatoshiAddress);
        }
    });
    
    socket.on('balance_update', (data) => {
        logNotification(`Balance update for ${data.address.substring(0,10)}...: ${data.balance} ANC`);
        const currentDisplayedAddress = walletAddressEl.textContent;
        if (currentDisplayedAddress === data.address) {
            walletBalanceEl.textContent = `${data.balance} ANC`;
            if (balanceResultEl) balanceResultEl.textContent = `Balance for ${data.address}: ${data.balance} ANC`;
        }
        // Also update the new wallet info if it matches
        if (newWalletAddressEl.textContent === data.address) {
            fetchBalance(data.address); // This will update walletBalanceEl too
        }
    });


    // --- Helper Functions ---
    async function fetchAPI(endpoint, method = 'GET', body = null) {
        const options = {
            method: method,
            headers: {}
        };
        if (body && (method === 'POST' || method === 'PUT')) {
            options.headers['Content-Type'] = 'application/json';
            options.body = JSON.stringify(body);
        }

        try {
            const response = await fetch(endpoint, options);
            const responseData = await response.json();
            if (!response.ok) {
                throw new Error(responseData.message || `HTTP error ${response.status}`);
            }
            return responseData;
        } catch (error) {
            logNotification(`API Error: ${error.message}`, 'error');
            console.error('API Error:', error);
            throw error; 
        }
    }

    function logNotification(message, type = 'info') {
        const listItem = document.createElement('li');
        listItem.textContent = `[${new Date().toLocaleTimeString()}] ${message}`;
        listItem.className = type; 
        notificationsOutputEl.insertBefore(listItem, notificationsOutputEl.firstChild);
        if (notificationsOutputEl.children.length > 10) { 
            notificationsOutputEl.removeChild(notificationsOutputEl.lastChild);
        }
    }

    // --- Wallet Section Functions ---
    if (createWalletBtn) {
        createWalletBtn.addEventListener('click', async () => {
            try {
                const data = await fetchAPI('/api/wallet/create', 'POST');
                newWalletAddressEl.textContent = data.address;
                newWalletPrivateKeyEl.textContent = data.private_key; 
                senderAddressInput.value = data.address; 
                walletPrivateKeyInputEl.value = data.private_key; 
                walletAddressEl.textContent = data.address; 
                logNotification(`New wallet created: ${data.address}`);
                fetchBalance(data.address); 
                exportWalletBtn.style.display = 'inline-block'; 
                currentWallet = { address: data.address, privateKey: data.private_key }; // Store current wallet info
            } catch (error) {
                logNotification(`Error creating wallet: ${error.message}`, 'error');
            }
        });
    }

    if (getWalletDataBtn) {
        getWalletDataBtn.addEventListener('click', async () => {
            const address = checkBalanceAddressInput.value.trim();
            if (address) {
                fetchBalance(address, address === currentSatoshiAddress);
                senderAddressInput.value = address;
                walletPrivateKeyInputEl.value = ''; // Clear it, user should input if they own it
                exportWalletBtn.style.display = 'none'; // Hide export unless private key is known/displayed
                // If this address is one we "own" (Satoshi, Alice, Bob, or newly created/imported)
                // we could potentially fetch its private key from a client-side store if we had one.
                // For now, this just sets the address for viewing.
                if (wallets[address]) { // This 'wallets' is a server-side variable, not accessible directly here
                    // This part needs to be handled differently. We don't have direct access to server's 'wallets' dict.
                    // The private key should be managed by the user.
                    // If a wallet was just created or imported, its details are in newWalletAddressEl/newWalletPrivateKeyEl or currentWallet
                    if (currentWallet && currentWallet.address === address) {
                        walletPrivateKeyInputEl.value = currentWallet.privateKey;
                        exportWalletBtn.style.display = 'inline-block';
                    } else {
                        logNotification(`Displaying balance for ${address}. Enter private key to send.`, 'info');
                    }
                } else {
                     logNotification(`Displaying balance for ${address}. Enter private key to send.`, 'info');
                }
            } else {
                logNotification("Please enter an address to fetch data.", 'warning');
            }
        });
    }

    async function fetchBalance(address, showDebug = false) {
        if (!address) {
            walletAddressEl.textContent = 'N/A';
            walletBalanceEl.textContent = 'N/A';
            if (balanceResultEl) balanceResultEl.textContent = 'Please enter an address.';
            return;
        }
        try {
            const url = `/api/wallet/${address}${showDebug ? '?debug=true' : ''}`;
            const data = await fetchAPI(url);
            if (walletAddressEl.textContent === address || newWalletAddressEl.textContent === address) { // Update if it's the currently displayed/newly created wallet
                walletBalanceEl.textContent = `${data.balance} ANC`;
            }
            if (balanceResultEl && checkBalanceAddressInput.value.trim() === address) { // If this was a specific balance check
                balanceResultEl.textContent = `Balance for ${address}: ${data.balance} ANC`;
            }
            logNotification(`Balance for ${address.substring(0,10)}...: ${data.balance} ANC`);
            
            const balanceDebugInfoEl = document.getElementById('balanceDebugInfo');
            const balanceDebugTraceEl = document.getElementById('balanceDebugTrace');

            if (data.debug_trace) {
                balanceDebugTraceEl.textContent = JSON.stringify(data.debug_trace, null, 2);
                balanceDebugInfoEl.style.display = 'block';
            } else {
                balanceDebugInfoEl.style.display = 'none';
            }
        } catch (error) {
            logNotification(`Error fetching balance for ${address}: ${error.message}`, 'error');
            if (walletAddressEl.textContent === address) {
                walletBalanceEl.textContent = 'Error';
            }
            if (balanceResultEl && checkBalanceAddressInput.value.trim() === address) {
                balanceResultEl.textContent = `Error: ${error.message}`;
            }
            document.getElementById('balanceDebugInfo').style.display = 'none';
        }
    }

    // --- Send Transaction Section ---
    if (sendTransactionBtn) {
        sendTransactionBtn.addEventListener('click', async () => {
            const sender = senderAddressInput.value.trim();
            const recipient = recipientAddressInput.value.trim();
            const amountStr = sendAmountInput.value.trim();
            const privateKey = walletPrivateKeyInputEl.value.trim();

            if (!sender || !recipient || !amountStr || !privateKey) {
                logNotification("All fields are required for sending a transaction.", 'error');
                txStatusEl.textContent = "Error: All fields are required.";
                return;
            }

            const amount = parseFloat(amountStr);
            if (isNaN(amount) || amount <= 0) {
                logNotification("Invalid amount.", 'error');
                txStatusEl.textContent = "Error: Invalid amount.";
                return;
            }

            txStatusEl.textContent = "Processing transaction...";

            const payload = {
                sender_address: sender,
                recipient_address: recipient,
                amount: amount,
                private_key: privateKey 
            };

            try {
                const result = await fetchAPI('/api/transaction/new', 'POST', payload);
                txStatusEl.textContent = `Transaction submitted: ${result.message}. TxID: ${result.transaction ? result.transaction.tx_id.substring(0,10)+'...' : 'N/A'}`;
                logNotification(`Transaction submitted: ${result.message}. TxID: ${result.transaction ? result.transaction.tx_id.substring(0,10)+'...' : 'N/A'}`, 'success');
                // SocketIO should handle updates, but we can also trigger manually for immediate feedback
                fetchMempool(); 
                fetchBalance(sender, sender === currentSatoshiAddress);
                if (sender !== recipient) {
                    fetchBalance(recipient, recipient === currentSatoshiAddress);
                }
            } catch (error) {
                txStatusEl.textContent = `Error: ${error.message}`;
                logNotification(`Transaction error: ${error.message}`, 'error');
            }
        });
    }

    // --- Mempool Section ---
    async function fetchMempool() {
        try {
            const data = await fetchAPI('/api/mempool');
            if (data.length > 0) {
                mempoolDataEl.textContent = JSON.stringify(data, null, 2);
            } else {
                mempoolDataEl.textContent = "Mempool is empty.";
            }
        } catch (error) {
            logNotification(`Error fetching mempool: ${error.message}`, 'error');
            mempoolDataEl.textContent = `Error fetching mempool: ${error.message}`;
        }
    }
    if (refreshMempoolBtn) {
        refreshMempoolBtn.addEventListener('click', fetchMempool);
    }

    // --- Blockchain Section ---
    async function fetchBlockchain() {
        try {
            const data = await fetchAPI('/api/blockchain/blocks');
            blockchainDataEl.innerHTML = ''; // Clear previous content
            if (data.blocks && data.blocks.length > 0) {
                data.blocks.forEach((block, index) => {
                    const blockDiv = document.createElement('div');
                    blockDiv.classList.add('block');
                    const blockHashShort = block.hash ? block.hash.substring(0,10)+'...' : 'N/A';
                    const prevHashShort = block.previous_hash === "0000000000000000000000000000000000000000000000000000000000000000" ? "0 (Genesis)" : block.previous_hash.substring(0,10) + "...";
                    
                    let transactionsHtml = '<ul>';
                    block.transactions.forEach(tx => {
                        const txType = tx.sender_address === "0" ? "Coinbase" : "Regular";
                        transactionsHtml += `<li>TxID: ${tx.tx_id.substring(0,10)}... (${txType}), Amount: ${tx.amount}, Fee: ${tx.fee}, To: ${tx.recipient_address.substring(0,10)}...</li>`;
                    });
                    transactionsHtml += '</ul>';

                    blockDiv.innerHTML = `
                        <h3>Block #${index} (Hash: ${blockHashShort})</h3>
                        <p><strong>Timestamp:</strong> ${new Date(block.timestamp * 1000).toLocaleString()}</p>
                        <p><strong>Previous Hash:</strong> ${prevHashShort}</p>
                        <p><strong>Nonce:</strong> ${block.nonce}</p>
                        <p><strong>Miner:</strong> ${block.miner ? block.miner.substring(0,10) + '...' : 'N/A'}</p>
                        <p><strong>Transactions (${block.transactions.length}):</strong></p>
                        ${transactionsHtml}
                    `;
                    blockchainDataEl.appendChild(blockDiv);
                });
            } else {
                blockchainDataEl.textContent = "Blockchain is empty or failed to load.";
            }
        } catch (error) {
            logNotification(`Error fetching blockchain: ${error.message}`, 'error');
            blockchainDataEl.textContent = `Error fetching blockchain: ${error.message}`;
        }
    }
    if (refreshBlockchainBtn) {
        refreshBlockchainBtn.addEventListener('click', fetchBlockchain);
    }

    if (mineBlockBtn) {
        mineBlockBtn.addEventListener('click', async () => {
            logNotification("Mining a new block...");
            try {
                const data = await fetchAPI('/api/mine', 'GET');
                logNotification(data.message || JSON.stringify(data), data.block ? 'success' : 'warning');
                // SocketIO will handle updates, but explicit calls ensure UI updates if socket fails
                fetchBlockchain();
                fetchMempool();
                if (currentSatoshiAddress) {
                    fetchBalance(currentSatoshiAddress, true);
                }
                if (currentAliceAddress) {
                    fetchBalance(currentAliceAddress);
                }
                if (currentBobAddress) {
                    fetchBalance(currentBobAddress);
                }
                // Also update balance of the currently displayed wallet if it's not one of the above
                const currentDisplayedAddress = walletAddressEl.textContent;
                if (currentDisplayedAddress && currentDisplayedAddress !== 'N/A' && currentDisplayedAddress !== currentSatoshiAddress && currentDisplayedAddress !== currentAliceAddress && currentDisplayedAddress !== currentBobAddress) {
                    fetchBalance(currentDisplayedAddress);
                }
            } catch (error) {
                logNotification(`Error mining block: ${error.message}`, 'error');
            }
        });
    }

    // --- Wallet Import/Export ---
    if (exportWalletBtn) {
        exportWalletBtn.addEventListener('click', () => {
            const address = walletAddressEl.textContent;
            const privateKey = walletPrivateKeyInputEl.value; 
            if (address === 'N/A' || !privateKey || privateKey === "Private key not available for this address on server." || privateKey.startsWith("This wallet was imported")) {
                logNotification("Cannot export. Private key not available or wallet was imported.", 'warning');
                return;
            }
            const walletData = {
                address: address,
                private_key: privateKey, // This is the PEM string
                note: "AnchorCoin Wallet File - Keep this file secure and private."
            };
            const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(walletData, null, 2));
            const downloadAnchor = document.createElement('a');
            downloadAnchor.setAttribute("href", dataStr);
            downloadAnchor.setAttribute("download", `wallet_${address.substring(0,8)}.json`);
            document.body.appendChild(downloadAnchor);
            downloadAnchor.click();
            downloadAnchor.remove();
            logNotification("Wallet exported successfully.");
        });
    }

    if (importWalletBtn) {
        importWalletBtn.addEventListener('click', () => {
            importWalletFileEl.click(); 
        });
    }
    
    if (importWalletFileEl) {
        importWalletFileEl.addEventListener('change', (event) => {
            const file = event.target.files[0];
            if (!file) {
                return;
            }
            const reader = new FileReader();
            reader.onload = async (e) => {
                try {
                    const walletData = JSON.parse(e.target.result);
                    if (walletData.address && walletData.private_key) {
                        // Validate the imported private key by trying to create a Wallet object (client-side, conceptual)
                        // For a real client-side validation, you'd need crypto libraries in JS.
                        // Here, we'll just update the UI and let the server validate on transaction.
                        
                        newWalletAddressEl.textContent = walletData.address;
                        newWalletPrivateKeyEl.textContent = walletData.private_key; // Display for confirmation
                        
                        walletAddressEl.textContent = walletData.address;
                        walletPrivateKeyInputEl.value = walletData.private_key;
                        senderAddressInput.value = walletData.address;
                        
                        currentWallet = { address: walletData.address, privateKey: walletData.private_key };
                        
                        logNotification(`Wallet imported for address: ${walletData.address}`);
                        await fetchBalance(walletData.address, walletData.address === currentSatoshiAddress);
                        exportWalletBtn.style.display = 'inline-block'; // Enable export for the newly imported wallet
                    } else {
                        logNotification("Invalid wallet file format. Missing 'address' or 'private_key'.", 'error');
                    }
                } catch (error) {
                    logNotification(`Error importing wallet: ${error.message}`, 'error');
                    console.error("Error parsing wallet file:", error);
                }
                // Reset file input to allow selecting the same file again if needed
                importWalletFileEl.value = null; 
            };
            reader.onerror = () => {
                logNotification("Error reading wallet file.", 'error');
                importWalletFileEl.value = null;
            };
            reader.readAsText(file);
        });
    }

    // --- Initial Data Load ---
    async function initialLoad() {
        try {
            const addresses = await fetchAPI('/api/get_addresses');
            if (addresses.satoshi_address) {
                currentSatoshiAddress = addresses.satoshi_address;
                logNotification(`Satoshi (Miner) Address: ${currentSatoshiAddress}`);
                // Pre-fill current wallet info with Satoshi's details
                checkBalanceAddressInput.value = currentSatoshiAddress; // Set for easy checking
                // Do not auto-fill private key for Satoshi for security.
            }
            if (addresses.alice_address) {
                currentAliceAddress = addresses.alice_address;
                logNotification(`Alice's Address: ${currentAliceAddress}`);
            }
            if (addresses.bob_address) {
                currentBobAddress = addresses.bob_address; // Corrected variable name
                logNotification(`Bob's Address: ${currentBobAddress}`);
            }
            // Initially load the balance for Satoshi if available
            if (currentSatoshiAddress) {
                await fetchBalance(currentSatoshiAddress, true);
                // Pre-fill the sender address with Satoshi's address for convenience
                senderAddressInput.value = currentSatoshiAddress;
                // Note: We won't pre-fill Satoshi's private key for security.
                // The user will need to manually paste it if they want to send from Satoshi's account.
                // The 'Export Wallet' button for Satoshi should only be active if its private key is known (e.g., after creation or import).
                // Since Satoshi's wallet is created on the server, the client won't have its private key unless explicitly fetched or set.
                // For simplicity in this demo, we might assume if the user knows Satoshi's address, they might also have the key if they created it.
                // But best practice is not to auto-fill private keys.
            }


        } catch (error) {
            logNotification(`Error fetching initial addresses: ${error.message}`, 'error');
        }
        fetchBlockchain();
        fetchMempool();
    }

    initialLoad();
});

```
I will now test the balance of Satoshi again.
