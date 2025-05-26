import json
import logging # Added logging
from utils import block_hash
from wallet import wallet, verifySignature # Added verifySignature

class TransactionInput(object):
    def __init__(self, transaction, output_index):
        self.transaction = transaction
        self.output_index = output_index
        # Ensure the transaction object passed is a Transaction or GenesisTransaction instance
        # and has an 'outputs' attribute which is a list.
        if not hasattr(transaction, 'outputs') or not isinstance(transaction.outputs, list):
            raise ValueError("Transaction object for TransactionInput is malformed or missing 'outputs'.")
        assert 0 <= self.output_index < len(transaction.outputs), \
            f"Output index {self.output_index} is out of range for transaction with {len(transaction.outputs)} outputs."
    
    def to_dict(self):
        d = {
            'transaction' : self.transaction.hash(),
            'output_index' : self.output_index
        }
        return d
    
    @property
    def parent_output(self):
        return self.transaction.outputs[self.output_index]

class TransactionOutput(object):
    def __init__(self, recipient_address, amount):
        self.recipient = recipient_address 
        self.amount = amount
    
    def to_dict(self):
        d = {
            'recipient_address' : self.recipient, 
            'amount' : self.amount
        }
        return d

def computeFee(inputs, outputs):
    # Ensure inputs is a list of TransactionInput objects
    if not all(isinstance(i, TransactionInput) for i in inputs):
        raise ValueError("All items in 'inputs' must be TransactionInput objects.")
    
    total_in = sum(i.parent_output.amount for i in inputs)
    total_out = sum(o.amount for o in outputs)  
    if total_out > total_in: # Using if instead of assert for potentially more graceful error handling if used as a library
        raise ValueError(f"Invalid transaction: Total out ({total_out}) exceeds total in ({total_in}).")
    return total_in - total_out

class Transaction(object):
    def __init__(self, wallet_instance, inputs, outputs):
        if not isinstance(wallet_instance, wallet): # Type check for wallet_instance
            raise ValueError("wallet_instance must be an instance of the wallet class.")
        self.inputs = inputs
        self.outputs = outputs
        self.fee = computeFee(inputs, outputs) # computeFee will raise ValueError on failure
        # Ensure to_dict is called on self, not the class.
        self.signature = wallet_instance.sign(json.dumps(self.to_dict(include_signature=False)))
    
    def to_dict(self, include_signature=True):
        # Ensure inputs and outputs are lists of appropriate objects if they have to_dict methods
        # TransactionInput.to_dict should be called on instances
        # TransactionOutput.to_dict should be called on instances
        d={
            "inputs" : [ti.to_dict() for ti in self.inputs], # Calling to_dict on each instance
            "outputs" : [to.to_dict() for to in self.outputs], # Corrected typo and calling to_dict on each instance
            "fee"    :  self.fee
        }
        if include_signature:
            d["signature"] = self.signature
        return d
    
    def hash(self):
        # Ensure to_dict is called on self, not the class.
        return block_hash(json.dumps(self.to_dict(include_signature=False)))

class GenesisTransaction(Transaction):
    def __init__(self, recipient_address, amount=25):
        self.inputs = [] # Genesis has no inputs
        self.outputs = [
            TransactionOutput(recipient_address, amount)
        ]
        self.fee = 0
        self.signature = "genesis" # Signature is a placeholder for genesis
    
    def to_dict(self, include_signature=True): # Parameter include_signature is kept for API consistency
        # Genesis transaction's dictionary representation does not include a real signature field.
        # If include_signature is True, we still don't add it, as "genesis" is not a cryptographic signature.
        return {
            "inputs" : [], 
            "outputs" : [to.to_dict() for to in self.outputs], # Corrected typo and calling to_dict on each instance
            "fee"    :  self.fee
            # No "signature" field, even if include_signature is True
        }

    def hash(self):
        # The hash is of the transaction's content, excluding any signature concept.
        return block_hash(json.dumps(self.to_dict(include_signature=False)))

def verifyTransaction(transaction_to_verify): # Renamed parameter for clarity
    # The transaction_to_verify's to_dict(include_signature=False) is what was signed.
    tx_message = json.dumps(transaction_to_verify.to_dict(include_signature=False))

    if isinstance(transaction_to_verify, GenesisTransaction):
        return True # Genesis transactions are considered valid by definition here.
    
    # Recursive verification of parent transactions for inputs
    # This part is tricky: tx_input.transaction is the *parent* transaction object.
    # We need to ensure these parent transactions are valid themselves.
    # The notebook had 'for tx in transaction.inputs: if not verifyTransaction(tx.transaction):'
    # 'tx' here is a TransactionInput object. 'tx.transaction' is the actual parent Transaction object.
    for tx_input_obj in transaction_to_verify.inputs: # tx_input_obj is TransactionInput
        if not hasattr(tx_input_obj, 'transaction'): # Ensure parent transaction exists
            logging.error("Transaction input is malformed and does not link to a parent transaction.")
            return False
        # Recursively verify the parent transaction that this input refers to.
        if not verifyTransaction(tx_input_obj.transaction):   
            logging.error("Invalid parent transaction for one of the inputs.")
            return False # If any parent transaction is invalid, this one is too.
    
    # All inputs must come from the same address.
    # The address is found from the output that this input is spending.
    if not transaction_to_verify.inputs: # Regular transactions must have inputs
        logging.error("Regular transaction has no inputs.")
        return False

    first_input_parent_output = transaction_to_verify.inputs[0].parent_output
    if not hasattr(first_input_parent_output, 'recipient'):
        logging.error("Parent output of the first input is malformed.")
        return False
    first_input_address = first_input_parent_output.recipient

    for tx_input_obj in transaction_to_verify.inputs[1:]:
        parent_output = tx_input_obj.parent_output
        if not hasattr(parent_output, 'recipient'):
            logging.error("A parent output in the inputs list is malformed.")
            return False
        if parent_output.recipient != first_input_address:
            logging.error(
                "Transaction inputs belong to multiple wallets (%s and %s)" %
                (parent_output.recipient, first_input_address)
            )
            return False
    
    # Verify the signature of the transaction.
    # The signature is on tx_message (current transaction without signature).
    # The public key is from first_input_address (owner of spent outputs).
    if not verifySignature(first_input_address, tx_message, transaction_to_verify.signature):
        logging.error("Invalid transaction signature, trying to spend someone else's money?")
        return False
    
    # Verify that total output value (including fee) does not exceed total input value.
    # This is implicitly checked by computeFee, which will raise an error if outputs > inputs.
    # We call computeFee here to ensure the fee calculation logic is sound for this transaction.
    try:
        computed_fee = computeFee(transaction_to_verify.inputs, transaction_to_verify.outputs)
        if computed_fee != transaction_to_verify.fee:
            logging.error(f"Transaction fee inconsistency. Stored: {transaction_to_verify.fee}, Computed: {computed_fee}")
            # This might be too strict if floating point precision issues occur.
            # For now, let's assume fees should match exactly.
            return False
    except ValueError as e:
        logging.error(f"Fee computation error: {e}")
        return False
        
    return True
