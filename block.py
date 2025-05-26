import json
import logging
from transaction import Transaction, GenesisTransaction, TransactionInput, TransactionOutput, verifyTransaction, computeFee # Added computeFee
from utils import mine, block_hash
from wallet import verifySignature # Added verifySignature

BLOCK_INCENTIVE = 25
DIFFICULTY = 2

def compute_total_fee(transactions):
    return sum(t.fee for t in transactions)

class Block(object):
    def __init__(self, transactions, ancestor, miner_address, skip_verify=False):
        reward = compute_total_fee(transactions) + BLOCK_INCENTIVE
        # Ensure miner_address is used for the reward transaction
        self.transactions = [GenesisTransaction(miner_address, amount=reward)] + transactions
        self.ancestor = ancestor

        if not skip_verify:
            # verifyTransaction is defined in transaction.py, ensure it's imported
            assert all(map(verifyTransaction, transactions))
        
        json_block = json.dumps(self.to_dict(include_hash = False))
        self.nonce, _ = mine(json_block, DIFFICULTY) # mine is from utils.py
        self.hash = block_hash(json_block + self.nonce) # block_hash is from utils.py
    
    def fee(self): # This method seems to calculate total fee of all transactions including the genesis one for the block.
        return compute_total_fee(self.transactions) 
    
    def to_dict(self, include_hash=False):
        d = {
            # Transaction.to_dict needs to be callable for each transaction object
            "transactions" : list(map(lambda t: t.to_dict(), self.transactions)),
            "previous_block" : self.ancestor.hash if self.ancestor else None # Handle genesis block case
        }
        if include_hash:
            d["nonce"] = self.nonce
            d["hash"] = self.hash
        return d
    
class GenesisBlock(Block):       
    def __init__(self, miner_address):
        # GenesisBlock has no real "transactions" in the list initially, reward is handled by its own GenesisTransaction
        super().__init__(transactions=[], ancestor=None, miner_address=miner_address, skip_verify=True) # skip_verify for initial empty list
        
    def to_dict(self, include_hash=True): # Default include_hash to True as per notebook
        d = {
            "transactions" : list(map(lambda t: t.to_dict(), self.transactions)), # Should include the block's own genesis transaction
            "genesis_block" : True,
        }
        if include_hash == True: # Explicitly check True
            d["nonce"] = self.nonce
            d["hash"] = self.hash
        return d

def verify_block(current_block, genesis_block_instance, used_outputs_set=None): # Renamed for clarity
    if used_outputs_set is None:
        used_outputs_set = set() # Initialize as a set

    prefix = '1' * DIFFICULTY # DIFFICULTY is a global constant in this file
    if not current_block.hash.startswith(prefix):
        logging.error("Block hash (%s) doesn't start with prefix %s" % (current_block.hash, prefix))
        return False
    
    # verifyTransaction needs to be imported or defined. It's in transaction.py
    # We need to skip the first transaction (the block's own genesis/reward transaction) for this specific check,
    # as verifyTransaction is designed for user-submitted transactions.
    # The block's genesis transaction is verified by checking its amount later.
    if not all(map(verifyTransaction, current_block.transactions[1:])): # Check only user transactions
        logging.error("Verification failed for one of the user transactions in the block.")
        return False
    
    for transaction_in_block in current_block.transactions: # Renamed for clarity
        for tx_input in transaction_in_block.inputs: # Renamed for clarity
            # parent_output should be an actual TransactionOutput object
            # We need to ensure that TransactionInput correctly resolves parent_output
            # If it's already a hash, this check will fail.
            # Based on TransactionInput, parent_output IS a TransactionOutput object.
            # The issue might be how `used_outputs_set` stores these.
            # For simplicity, let's store a unique representation of the output.
            # A tuple of (transaction_hash, output_index) could work if parent_output objects are not directly hashable for sets.
            # However, the notebook implies direct object comparison might work if objects are consistently reused.
            # Let's assume parent_output objects can be added to a set.
            # If TransactionOutput is not hashable, this will be an issue.
            # Let's create a unique tuple for the set: (tx_hash, output_index)
            output_tuple = (tx_input.transaction.hash(), tx_input.output_index)
            if output_tuple in used_outputs_set:
                logging.error("Transaction uses an already spent output: %s" % json.dumps(tx_input.parent_output.to_dict()))
                return False
            used_outputs_set.add(output_tuple)
    
    if not (current_block.hash == genesis_block_instance.hash): # Use .hash for comparison
        if not current_block.ancestor: # Check if ancestor exists
             logging.error("Non-genesis block has no ancestor.")
             return False
        if not verify_block(current_block.ancestor, genesis_block_instance, used_outputs_set): # Pass the set recursively
            logging.error("Failed to validate ancestor block")
            return False
        
    tx0 = current_block.transactions[0]
    if not isinstance(tx0, GenesisTransaction): # This should be the block's reward transaction
        logging.error("Transaction 0 is not a GenesisTransaction (block reward)")
        return False
    if not len(tx0.outputs) == 1:
        logging.error("Transactions 0 (block reward) doesn't have exactly 1 output")
        return False
    
    # compute_total_fee is defined in this file. It should apply to user transactions (transactions[1:])
    reward = compute_total_fee(current_block.transactions[1:]) + BLOCK_INCENTIVE
    if not tx0.outputs[0].amount == reward:
        logging.error("Invalid amount in transaction 0 (block reward): %s, expected %s" % (tx0.outputs[0].amount, reward))
        return False
    
    for i, tx in enumerate(current_block.transactions):
        if i == 0: # This is the block's own genesis (reward) transaction
            if not isinstance(tx, GenesisTransaction):
                logging.error("Non-genesis transaction (block reward type) at index 0")
                return False  
        elif isinstance(tx, GenesisTransaction): # User transactions should not be GenesisTransaction
            logging.error("User submitted GenesisTransaction (hash=%s) at index %d != 0", tx.hash(), i)
            return False
    return True

def collectTransaction(block_instance, genesis_block_instance): # Renamed for clarity
    transactions_list = [] + block_instance.transactions # Renamed for clarity
    if block_instance.hash != genesis_block_instance.hash:
        if block_instance.ancestor: # Check if ancestor exists
            transactions_list += collectTransaction(block_instance.ancestor, genesis_block_instance)
    return transactions_list

# Function from notebook, seems to be for calculating balance from a list of transactions
# This was defined globally in the notebook but seems more like a utility that could go into utils.py
# or be part of main.py if it's only for display/testing.
# For now, let's assume it's needed by main.py and main.py will import it from wherever it's placed.
# To keep block.py focused, I will NOT include computeBalance here. It was used in the example section.
# computeBalance was defined in cell [18] of the notebook.
# verifyTransaction was defined in cell [19] - it is in transaction.py
# The Block class definition uses `verifyTransaction` and `mine`.
# The verify_block function uses `verifyTransaction`.
# The example usage in main.py will need `computeBalance`.
