AnchorCoin
  A blockchain implementation in Python for educational purposes.

Overview
  AnchorCoin is a simplified blockchain implementation that demonstrates the core concepts of blockchain technology including transactions, mining, and consensus. This project is built for learning and experimentation rather than production use.

Features
  Blockchain data structure with proof-of-work consensus
  Genesis block and transaction creation
  Transaction system with inputs and outputs (UTXO model)
  Digital signatures for transaction verification
  Wallet management
  Block mining with adjustable difficulty
  Transaction and block verification

Core Components
  Wallet
    The wallet component manages public/private keypairs and handles transaction signing.

Transactions
  GenesisTransaction: Special first transaction that creates initial coins
  Transaction: Regular transaction with inputs and outputs
  TransactionInput: References to previous transaction outputs
  TransactionOutput: Destination addresses and amounts

Blocks
  GenesisBlock: First block in the chain with no ancestor
  Block: Contains transactions and links to the previous block
  Mining: Proof-of-work mechanism to secure the blockchain

Blockchain Fundamentals
  AnchorCoin implements the core principles of blockchain technology:

  1.Decentralized Ledger: All transactions are recorded in blocks linked together
  2.Consensus Mechanism: Proof-of-work mining ensures agreement on transaction history
  3.Immutable Records: Cryptographic links between blocks prevent tampering
  4.Transparent Verification: Anyone can verify the validity of transactions and blocks
