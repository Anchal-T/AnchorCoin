import json # For any json operations if needed, though example primarily uses class instances
import logging # For seeing logs from other modules

# From utils.py
from utils import sha256, mine, block_hash, computeBalance # block_hash might not be directly used in main, but good to list if examples did

# From wallet.py
from wallet import wallet, verifySignature

# From transaction.py
from transaction import Transaction, TransactionInput, TransactionOutput, GenesisTransaction, computeFee, verifyTransaction

# From block.py
from block import Block, GenesisBlock, verify_block, collectTransaction, BLOCK_INCENTIVE, DIFFICULTY # DIFFICULTY might be used if we re-run mine examples

# Setup basic logging configuration for the main script to see output from modules
logging.basicConfig(level=logging.INFO)


# Definition of computeBalance (from notebook cell [18])
# This function is now in utils.py
# def computeBalance(wallet_address, transactions_list): # Renamed for clarity
#     balance = 0
#     for t in transactions_list:
#         for txin in t.inputs:
#             # parent_output should be a TransactionOutput object
#             if hasattr(txin, 'parent_output') and txin.parent_output.recipient == wallet_address:
#                 balance -= txin.parent_output.amount
#         
#         for txout in t.outputs:
#             if txout.recipient == wallet_address:
#                 balance += txout.amount
#     return balance

def run_examples():
    print("Running sha256 and mine examples (from cells [3], [6])")
    # Example from cell [3] - sha256 with nonce
    message = 'hello world'
    found_nonce_example3 = -1
    for nonce_val in range(1000): # Renamed nonce to nonce_val to avoid conflict
        digest = sha256(message + str(nonce_val))
        if digest.startswith('11'):
            print(f"Found nonce for cell [3] example = {nonce_val}")
            found_nonce_example3 = nonce_val
            break
    if found_nonce_example3 != -1:
        print(sha256(message + str(found_nonce_example3)))
    else:
        print("Nonce for cell [3] example not found in 1000 iterations.")

    # Example from cell [6] - mine function
    # Re-using DIFFICULTY from block.py for consistency if desired, or define locally.
    # Let's assume we use the global DIFFICULTY for this example.
    print(f"Mining with difficulty: {DIFFICULTY}") # Using DIFFICULTY from block.py
    example_mine_message = 'hello welp'
    nonce_val, nitters = mine(example_mine_message, difficulty=DIFFICULTY) # Use imported DIFFICULTY
    print(f"Mined '{example_mine_message}' with nonce {nonce_val} in {nitters} iterations.")
    print("-" * 30)

    print("Running wallet examples (from cell [9])")
    # Example from cell [9] - wallet creation and signing
    w1 = wallet()
    signature = w1.sign('foobar')
    print(f"Wallet 1 Address: {w1.address}")
    print(f"Signature for 'foobar': {signature}")
    assert verifySignature(w1.address, 'foobar', signature)
    print("Signature for 'foobar' verified successfully.")
    assert not verifySignature(w1.address, 'rogue message', signature)
    print("Signature for 'rogue message' correctly failed verification.")
    print("-" * 30)

    print("Running transaction examples (from cell [15], [16], [17])")
    # Setup wallets (as in cell [17])
    alice = wallet()
    bob = wallet()
    walter = wallet()
    print(f"Alice's address: {alice.address}")
    print(f"Bob's address: {bob.address}")
    print(f"Walter's address: {walter.address}")

    # Transaction example from cell [15] (and used in [17])
    # t1: GenesisTransaction for Alice
    t1_genesis_alice = GenesisTransaction(alice.address, amount=25) # amount from notebook context
    print(f"t1 (Genesis for Alice): {t1_genesis_alice.hash()}")

    # t2: Alice sends to Bob and self (fee calculation example from cell [15])
    # Inputs: from t1, output 0
    # Outputs: 2.0 to Bob, 22.0 to Alice. Expected fee: 25 - (2.0 + 22.0) = 1.0
    input_for_t2 = TransactionInput(t1_genesis_alice, 0)
    outputs_for_t2 = [
        TransactionOutput(bob.address, 2.0),
        TransactionOutput(alice.address, 22.0)
    ]
    t2_alice_to_bob_self = Transaction(alice, [input_for_t2], outputs_for_t2)
    print(f"t2 (Alice to Bob & self): {t2_alice_to_bob_self.hash()}, Fee: {t2_alice_to_bob_self.fee}")
    # Original notebook assertion: assert np.abs(t2.fee - 1.0) < 1e-5
    FEE_COMPARISON_EPSILON = 1e-5
    assert abs(t2_alice_to_bob_self.fee - 1.0) < FEE_COMPARISON_EPSILON, f"Fee for t2 is {t2_alice_to_bob_self.fee}, expected 1.0"
    print("Fee for t2 is correct.")

    # More transactions from cell [17]
    # t1 (redefined in cell [17] context, same as above)
    # t2 (redefined in cell [17], different amounts)
    # Alice -- 5 --> Bob
    #       -- 15 --> Alice (change)
    #       -- 5 --> Walter
    # Input: t1_genesis_alice, output 0. Total input amount: 25
    # Outputs: 5 to Bob, 15 to Alice, 5 to Walter. Total output amount: 5+15+5 = 25. Fee = 0.
    outputs_for_t2_v2 = [
        TransactionOutput(bob.address, 5.0),
        TransactionOutput(alice.address, 15.0),
        TransactionOutput(walter.address, 5.0)
    ]
    t2_v2_alice_multi_send = Transaction(alice, [TransactionInput(t1_genesis_alice, 0)], outputs_for_t2_v2)
    print(f"t2_v2 (Alice to Bob, self, Walter): {t2_v2_alice_multi_send.hash()}, Fee: {t2_v2_alice_multi_send.fee}")
    assert abs(t2_v2_alice_multi_send.fee - 0.0) < FEE_COMPARISON_EPSILON, "Fee for t2_v2 should be 0"


    # t3: Walter -- 5 --> Bob
    # Input: t2_v2, output 2 (Walter's 5.0)
    # Outputs: 5.0 to Bob. Fee = 0
    input_for_t3 = TransactionInput(t2_v2_alice_multi_send, 2) # t2_v2_alice_multi_send.outputs[2] is Walter's 5.0
    outputs_for_t3 = [TransactionOutput(bob.address, 5.0)]
    t3_walter_to_bob = Transaction(walter, [input_for_t3], outputs_for_t3)
    print(f"t3 (Walter to Bob): {t3_walter_to_bob.hash()}, Fee: {t3_walter_to_bob.fee}")
    assert abs(t3_walter_to_bob.fee - 0.0) < FEE_COMPARISON_EPSILON, "Fee for t3 should be 0"


    # t4: Bob -- 8 --> Walter, -- 1 --> Bob (change)
    # Inputs:
    #   1. t2_v2, output 0 (Bob's 5.0 from Alice)
    #   2. t3, output 0 (Bob's 5.0 from Walter)
    #   Total input for Bob: 5.0 + 5.0 = 10.0
    # Outputs: 8.0 to Walter, 1.0 to Bob. Total output amount: 8+1 = 9. Fee = 10 - 9 = 1.0
    inputs_for_t4 = [
        TransactionInput(t2_v2_alice_multi_send, 0), # Bob's 5.0 from Alice via t2_v2
        TransactionInput(t3_walter_to_bob, 0)      # Bob's 5.0 from Walter via t3
    ]
    outputs_for_t4 = [
        TransactionOutput(walter.address, 8.0),
        TransactionOutput(bob.address, 1.0)
    ]
    t4_bob_to_walter_self = Transaction(bob, inputs_for_t4, outputs_for_t4)
    print(f"t4 (Bob to Walter & self): {t4_bob_to_walter_self.hash()}, Fee: {t4_bob_to_walter_self.fee}")
    assert abs(t4_bob_to_walter_self.fee - 1.0) < FEE_COMPARISON_EPSILON, "Fee for t4 should be 1.0"
    
    transactions_for_balance_check = [t1_genesis_alice, t2_v2_alice_multi_send, t3_walter_to_bob, t4_bob_to_walter_self]
    print("-" * 30)

    print("Running computeBalance example (from cell [18])")
    # Using transactions defined above (t1_genesis_alice, t2_v2_alice_multi_send, t3_walter_to_bob, t4_bob_to_walter_self)
    # Alice: Starts with 25 (t1).
    #        In t2_v2: Spends 25 (input from t1). Receives 15. Net from t2_v2: -10.
    #        Alice total = 25 - 10 = 15.
    # Bob:   In t2_v2: Receives 5.
    #        In t3: Receives 5.
    #        In t4: Spends 10 (inputs from t2_v2 and t3). Receives 1. Net from t4: -9.
    #        Bob total = 5 + 5 - 9 = 1.
    # Walter: In t2_v2: Receives 5.
    #         In t3: Spends 5.
    #         In t4: Receives 8.
    #         Walter total = 5 - 5 + 8 = 8.
    # Fees: t2_v2 (0), t3 (0), t4 (1 to Bob's inputs, so it's part of Bob's spend).
    # The computeBalance function calculates based on inputs and outputs recorded in transactions.
    print(f"Alice  has {computeBalance(alice.address, transactions_for_balance_check):.2f} coins")
    print(f"Bob    has {computeBalance(bob.address, transactions_for_balance_check):.2f} coins")
    print(f"Walter has {computeBalance(walter.address, transactions_for_balance_check):.2f} coins")
    print("-" * 30)

    print("Running verifyTransaction examples (from cell [20])")
    # t1_genesis_alice was GenesisTransaction(alice.address)
    assert verifyTransaction(t1_genesis_alice), "Verification of t1_genesis_alice failed"
    print("Verification of t1_genesis_alice (Genesis Tx) succeeded.")
    assert verifyTransaction(t2_v2_alice_multi_send), "Verification of t2_v2_alice_multi_send failed"
    print("Verification of t2_v2_alice_multi_send succeeded.")
    assert verifyTransaction(t3_walter_to_bob), "Verification of t3_walter_to_bob failed"
    print("Verification of t3_walter_to_bob succeeded.")
    assert verifyTransaction(t4_bob_to_walter_self), "Verification of t4_bob_to_walter_self failed"
    print("Verification of t4_bob_to_walter_self succeeded.")
    print("-" * 30)

    print("Running Block creation and verification examples (from cells [23], [24])")
    # Wallets are already defined: alice, bob, walter
    # Genesis Block (mined by Alice)
    # BLOCK_INCENTIVE and DIFFICULTY are imported from block.py
    print(f"Block incentive: {BLOCK_INCENTIVE}, Difficulty: {DIFFICULTY}")
    
    # Create a new Alice for this block example to avoid address conflicts if previous examples modified wallet states
    # or to match notebook sequence where wallets might be redefined.
    # For simplicity, using existing alice, bob, walter.
    
    genesis_b = GenesisBlock(miner_address=alice.address)
    print(f"Genesis Block created by Alice: Hash {genesis_b.hash}, Fee {genesis_b.fee()}")
    # The fee for GenesisBlock includes its own reward transaction.
    # compute_total_fee([]) for transactions=[] is 0. So reward is BLOCK_INCENTIVE.
    # GenesisBlock's transactions list contains one GenesisTransaction for this reward.
    # Its fee is 0. So genesis_b.fee() which is compute_total_fee(genesis_b.transactions) should be 0.
    # Let's verify this understanding. The notebook output is "with fee=0".
    # The GenesisTransaction within GenesisBlock has amount=BLOCK_INCENTIVE and fee=0.
    # Block.fee() sums fees of transactions in self.transactions.
    # GenesisBlock.__init__ calls super().__init__(transactions=[],...).
    # Then self.transactions = [GenesisTransaction(miner_address, amount=reward)] + []
    # So self.transactions = [GenesisTransaction(alice.address, amount=BLOCK_INCENTIVE)]
    # The fee of this inner GenesisTransaction is 0. So Block.fee() for GenesisBlock should be 0.
    assert abs(genesis_b.fee() - 0.0) < FEE_COMPARISON_EPSILON, f"GenesisBlock fee is {genesis_b.fee()}, expected 0"

    # Transactions for Block 1 (from cell [23])
    # t1_block_ctx is the reward transaction from genesis_b for Alice
    t1_block_ctx = genesis_b.transactions[0] 
    assert isinstance(t1_block_ctx, GenesisTransaction)
    assert t1_block_ctx.outputs[0].recipient == alice.address
    assert t1_block_ctx.outputs[0].amount == BLOCK_INCENTIVE # Alice gets initial block incentive

    # t2_block_ctx: Alice (spends from t1_block_ctx) -> 5 to Bob, 15 to Alice, 5 to Walter
    # Input amount from t1_block_ctx is BLOCK_INCENTIVE (25)
    # Outputs: 5 (Bob) + 15 (Alice) + 5 (Walter) = 25. Fee = 0.
    tx_input_b1 = TransactionInput(t1_block_ctx, 0)
    tx_outputs_b1 = [
        TransactionOutput(bob.address, 5.0), 
        TransactionOutput(alice.address, 15.0), # Alice's change
        TransactionOutput(walter.address, 5.0)
    ]
    t2_block_ctx = Transaction(alice, [tx_input_b1], tx_outputs_b1)
    print(f"Transaction t2_block_ctx created for Block 1. Fee: {t2_block_ctx.fee}")
    assert abs(t2_block_ctx.fee - 0.0) < FEE_COMPARISON_EPSILON

    # Block 1 (mined by Walter, contains t2_block_ctx)
    # Transactions in block1 are [t2_block_ctx].
    # Fee from t2_block_ctx is 0. Reward for Walter = 0 (fees) + 25 (incentive) = 25.
    block1 = Block([t2_block_ctx], ancestor=genesis_b, miner_address=walter.address)
    print(f"Block 1 created by Walter: Hash {block1.hash}, Fee {block1.fee()}")
    # block1.fee() sums fees of its transactions.
    # block1.transactions = [GenesisTransaction_for_Walter_reward, t2_block_ctx]
    # Fee of GenesisTransaction_for_Walter_reward is 0. Fee of t2_block_ctx is 0. Sum = 0.
    # Notebook output for block1: "with fee=0"
    assert abs(block1.fee() - 0.0) < FEE_COMPARISON_EPSILON, f"Block 1 fee is {block1.fee()}, expected 0"


    # Transactions for Block 2 (from cell [23])
    # t3_block_ctx: Walter (spends from t2_block_ctx's output to Walter) -> 5 to Bob
    # t2_block_ctx.outputs[2] was 5.0 to Walter.
    # Input amount: 5.0. Outputs: 5.0 to Bob. Fee = 0.
    tx_input_b2_t3 = TransactionInput(t2_block_ctx, 2) # Walter's 5.0 from t2_block_ctx
    tx_outputs_b2_t3 = [TransactionOutput(bob.address, 5.0)]
    t3_block_ctx = Transaction(walter, [tx_input_b2_t3], tx_outputs_b2_t3)
    print(f"Transaction t3_block_ctx created for Block 2. Fee: {t3_block_ctx.fee}")
    assert abs(t3_block_ctx.fee - 0.0) < FEE_COMPARISON_EPSILON

    # t4_block_ctx: Bob (spends from t2_block_ctx's output to Bob AND t3_block_ctx's output to Bob) -> 8 to Walter, 1 to Bob
    # Inputs:
    #   1. t2_block_ctx.outputs[0] (Bob's 5.0 from Alice via t2_block_ctx)
    #   2. t3_block_ctx.outputs[0] (Bob's 5.0 from Walter via t3_block_ctx)
    #   Total input for Bob: 5.0 + 5.0 = 10.0
    # Outputs: 8.0 to Walter, 1.0 to Bob. Total output amount: 8+1 = 9. Fee = 1.0.
    tx_inputs_b2_t4 = [
        TransactionInput(t2_block_ctx, 0), # Bob's 5.0 from t2_block_ctx
        TransactionInput(t3_block_ctx, 0)  # Bob's 5.0 from t3_block_ctx
    ]
    tx_outputs_b2_t4 = [
        TransactionOutput(walter.address, 8.0),
        TransactionOutput(bob.address, 1.0) # Bob's change
    ]
    t4_block_ctx = Transaction(bob, tx_inputs_b2_t4, tx_outputs_b2_t4)
    print(f"Transaction t4_block_ctx created for Block 2. Fee: {t4_block_ctx.fee}")
    assert abs(t4_block_ctx.fee - 1.0) < FEE_COMPARISON_EPSILON
    
    # Block 2 (mined by Walter, contains [t3_block_ctx, t4_block_ctx])
    # Fees from transactions: t3_block_ctx (0) + t4_block_ctx (1) = 1.
    # Reward for Walter = 1 (fees) + 25 (incentive) = 26.
    block2_tx_list = [t3_block_ctx, t4_block_ctx]
    block2 = Block(block2_tx_list, ancestor=block1, miner_address=walter.address)
    print(f"Block 2 created by Walter: Hash {block2.hash}, Fee {block2.fee()}")
    # block2.fee() sums fees of its transactions:
    # block2.transactions = [GenesisTransaction_for_Walter_reward2, t3_block_ctx, t4_block_ctx]
    # Fees: GT (0) + t3 (0) + t4 (1) = 1.
    # Notebook output for block2: "with fee=1"
    assert abs(block2.fee() - 1.0) < FEE_COMPARISON_EPSILON, f"Block 2 fee is {block2.fee()}, expected 1"
    print("-" * 30)

    print("Running verify_block examples (from cell [24])")
    # Need to pass the actual genesis_b object, not just its hash
    assert verify_block(block1, genesis_b), "Verification of block1 failed"
    print("Verification of block1 succeeded.")
    # When verifying block2, used_outputs from block1's verification need to be considered.
    # The verify_block function in block.py creates a new set if None is passed.
    # For a chain, the set should be passed along.
    # The notebook example verify_block(block2, genesis_block) implies a fresh check for each,
    # but for full chain validation, outputs should accumulate.
    # My verify_block implementation passes the set recursively for ancestors.
    # A standalone call verify_block(block2, genesis_b) will start with a fresh used_output_set for block2's chain.
    assert verify_block(block2, genesis_b), "Verification of block2 failed"
    print("Verification of block2 succeeded.")
    print("-" * 30)

    print("Running collectTransaction and final balance check (from cell [25])")
    # Collect all transactions from block2 and its ancestors down to genesis_b
    all_transactions_in_chain = collectTransaction(block2, genesis_b)
    
    # Expected balances based on notebook cell [25]:
    # Alice: Mined genesis_b (gets 25). In t2_block_ctx, sends 5 to Bob, 5 to Walter, gets 15 back.
    #   - Initial reward in genesis_b: +25 (to Alice, as miner)
    #   - t2_block_ctx (initiated by Alice from genesis_b's output):
    #     - Input: 25 from Alice (from genesis_b reward)
    #     - Output: 5 to Bob, 15 to Alice, 5 to Walter.
    #   Alice's balance = (25 from mining genesis_b) - 25 (spent in t2_block_ctx) + 15 (change in t2_block_ctx) = 15.
    #
    # Bob: Gets 5 from Alice in t2_block_ctx. Gets 5 from Walter in t3_block_ctx.
    #      In t4_block_ctx, sends 8 to Walter, 1 to self (fee 1).
    #   - t2_block_ctx: +5 from Alice.
    #   - t3_block_ctx: +5 from Walter.
    #   - t4_block_ctx (initiated by Bob):
    #     - Inputs: 5 (from t2_block_ctx), 5 (from t3_block_ctx). Total 10.
    #     - Outputs: 8 (to Walter), 1 (to Bob). Total 9. Fee is 1.
    #   Bob's balance = 5 (from t2) + 5 (from t3) - 10 (spent in t4) + 1 (change in t4) = 1.
    #
    # Walter: Mined block1 (gets 25). Mined block2 (gets 25 from incentive + 1 from fees = 26).
    #         Gets 5 from Alice in t2_block_ctx. Sends 5 to Bob in t3_block_ctx. Gets 8 from Bob in t4_block_ctx.
    #   - Mining block1: +25 (Walter is miner for block1, this is tx0 of block1)
    #   - Mining block2: +26 (Walter is miner for block2, this is tx0 of block2, amount includes fees from t4_block_ctx)
    #   - t2_block_ctx: +5 from Alice.
    #   - t3_block_ctx (initiated by Walter):
    #     - Input: 5 (from t2_block_ctx)
    #     - Output: 5 (to Bob)
    #   - t4_block_ctx: +8 from Bob.
    #   Walter's balance = 25 (mine b1) + 26 (mine b2) + 5 (from t2) - 5 (spent in t3) + 8 (from t4) = 59.
    #
    # These balances are what `computeBalance` should find by summing inputs/outputs from `all_transactions_in_chain`.
    # `all_transactions_in_chain` includes:
    # - genesis_b.transactions[0] (Alice gets 25)
    # - block1.transactions[0] (Walter gets 25)
    # - block1.transactions[1] (t2_block_ctx: Alice -> Bob, Alice, Walter)
    # - block2.transactions[0] (Walter gets 26)
    # - block2.transactions[1] (t3_block_ctx: Walter -> Bob)
    # - block2.transactions[2] (t4_block_ctx: Bob -> Walter, Bob)

    print(f"Alice  has {computeBalance(alice.address, all_transactions_in_chain):.2f} coins")
    print(f"Bob    has {computeBalance(bob.address, all_transactions_in_chain):.2f} coins")
    print(f"Walter has {computeBalance(walter.address, all_transactions_in_chain):.2f} coins")
    print("-" * 30)
    print("All examples finished.")

if __name__ == "__main__":
    run_examples()
