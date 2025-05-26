```markdown
# AnchorCoin: A Simple Blockchain Showcase - User Guide

## 1. Project Overview

AnchorCoin is a simplified, educational blockchain implementation built with Python and Flask. This showcase demonstrates core blockchain concepts in action, allowing users to interact with a mini-cryptocurrency environment.

Key functionalities include:
- **Wallet Management:** Creating new wallets, viewing balances.
- **Transactions:** Sending AnchorCoins between wallets.
- **Mining:** Simulating the process of mining new blocks to confirm transactions.
- **Real-time Updates:** Utilizing WebSockets to see changes in the blockchain, mempool, and balances across connected clients instantly.
- **Blockchain Explorer:** Viewing the entire chain of blocks.
- **Mempool Viewing:** Observing transactions waiting to be mined.
- **Wallet Import/Export:** Basic functionality to save and load wallet credentials (for demonstration purposes).

This project is designed for educational purposes to illustrate how a basic blockchain operates.

## 2. Features

- **Wallet Creation:** Generate new public/private key pairs (addresses).
- **Transaction Creation:** Send AnchorCoins from one wallet to another.
- **Mempool:** A temporary holding area for unconfirmed transactions.
- **Mining:** A simplified Proof-of-Work (PoW) mechanism to bundle transactions into blocks and add them to the chain.
- **Block Reward:** Miners receive a reward for creating new blocks.
- **Transaction Fees:** Transactions include a small fee that goes to the miner.
- **Balance Checking:** View the current balance of any wallet address.
- **Blockchain Explorer:** View the entire chain of blocks and their contents.
- **Real-time Updates:** Changes to the blockchain, mempool, and balances are reflected in real-time across all connected clients using WebSockets.
- **Wallet Import/Export:** Ability to save and load wallet details (address and private key) via a JSON file. **Note:** This is a simplified implementation for demonstration; in a real-world scenario, private key management requires much higher security.

## 3. Prerequisites

Before you can run this application, ensure you have the following installed:

- **Python 3.x** (preferably 3.7 or higher)
- **pip** (Python package installer, usually comes with Python)

## 4. Setup and Running the Application

1.  **Clone the Repository (if applicable):**
    If you have received this as a set of files, ensure they are all in the same directory. If it's a Git repository:
    ```bash
    git clone <repository_url>
    cd <repository_name>
    ```

2.  **Create a Virtual Environment (Recommended):**
    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows: venv\Scripts\activate
    ```

3.  **Install Dependencies:**
    Navigate to the project directory in your terminal and run:
    ```bash
    pip install -r requirements.txt
    ```
    This will install Flask, Flask-SocketIO, PyCryptodome, and other necessary libraries.

4.  **Run the Flask Application:**
    In the project directory, execute:
    ```bash
    python app.py
    ```
    You should see output indicating the Flask development server is running, typically on `http://127.0.0.1:5000/`.

5.  **Access the Application:**
    Open your web browser and go to: `http://127.0.0.1:5000/`

## 5. How to Use the Showcase

### Wallet Management

*   **Creating a New Wallet:**
    *   Click the "Create New Wallet" button.
    *   Your new wallet's **Address** (public key) and **Private Key** will be displayed.
    *   **IMPORTANT:** The private key is like the password to your bank account. Keep it secret and safe. In this demo, it's displayed for ease of use, but in a real system, you would store it securely yourself.
    *   The new wallet's address and private key will also be automatically filled into the "Send Transaction" section for convenience.
    *   The "Export Wallet" button will become visible.

*   **Checking Balance:**
    *   Enter any wallet address into the "Enter your address" field under "Check Balance / View Wallet".
    *   Click "Get Wallet Data".
    *   The "Address" and "Balance" fields will update. If it's an address you created or imported in the current session, the private key might also fill (for demo purposes).

*   **Exporting a Wallet:**
    *   After creating a new wallet (or importing one), the "Export Wallet" button becomes active.
    *   Clicking it will download a `.json` file (e.g., `wallet_abcdef12.json`) containing the wallet's address and private key.
    *   **Security Warning:** This file contains your private key. Store it securely and do not share it. Anyone with this file can access your funds.

*   **Importing a Wallet:**
    *   Click the "Import Wallet from File" button.
    *   Select the `.json` file you previously exported.
    *   The wallet's address and private key will be loaded into the "New Wallet Info" and "Current Wallet Info" sections.
    *   The balance for the imported wallet will be fetched.

### Sending Transactions

1.  **Sender Address:** This field will often be auto-filled if you've just created or selected a wallet. Otherwise, paste the address you want to send from.
2.  **Private Key:** **Crucially, you must provide the private key corresponding to the "Sender Address"**. If you created a wallet, copy it from the "New Wallet Private Key" field. If you imported a wallet, it should be pre-filled.
3.  **Recipient Address:** Enter the address of the wallet you want to send AnchorCoins to. You can create another wallet or use one of the pre-generated Alice/Bob addresses displayed in the notifications.
4.  **Amount:** Enter the amount of AnchorCoin to send.
5.  **Click "Send Transaction".**
    *   You'll see a status message.
    *   The transaction will appear in the "Mempool" section if valid.
    *   Affected balances will update in real-time (due to WebSocket updates).

### Mining

1.  **Create Transactions:** First, create one or more transactions so there's something in the mempool to mine.
2.  **Click "Mine New Block".**
    *   The server will perform Proof-of-Work (this might take a few seconds depending on the `DIFFICULTY` setting).
    *   A "New block mined successfully!" message will appear in notifications.
    *   The "Blockchain Explorer" will update to show the new block.
    *   The "Mempool" will clear (or show remaining unconfirmed transactions).
    *   The miner (Satoshi, by default) will receive the block reward plus any transaction fees. Balances of senders and receivers in the mined transactions will also update.

### Real-time Interaction (Simulating Multiple Users)

This feature demonstrates how changes on one client are reflected on others connected to the same server.

1.  Open the application (`http://127.0.0.1:5000/`) in two separate browser windows or tabs. These represent two different users.
2.  **In Window 1 (User A):**
    *   Click "Create New Wallet". Note down Alice's address and private key.
    *   The "Sender Address" and "Private Key" fields will be auto-filled.
3.  **In Window 2 (User B):**
    *   Click "Create New Wallet". Note down Bob's address and private key.
4.  **Send a Transaction (Window 1 to Window 2):**
    *   In Window 1 (Alice's wallet), enter Bob's address (from Window 2) into the "Recipient Address" field.
    *   Enter an amount (e.g., 5). Alice should have 10 coins initially.
    *   Ensure Alice's private key is in the "Private Key (for sending)" field.
    *   Click "Send Transaction".
5.  **Observe:**
    *   **Both windows:** The "Mempool" section should update almost instantly, showing the new transaction. Balances for Alice (in Window 1) and Bob (in Window 2, if checking his balance) should update to reflect the pending transaction.
6.  **Mine the Block (either Window):**
    *   In either Window 1 or Window 2, click "Mine New Block".
7.  **Observe:**
    *   **Both windows:** The "Blockchain Explorer" will update with the new block. The "Mempool" will clear. The balances for Alice, Bob, and Satoshi (the miner) will update to reflect the confirmed transaction and mining reward.

### Exploring

*   **View Mempool:** Click "Refresh Mempool" (or wait for automatic updates) to see transactions waiting for confirmation.
*   **View Blockchain:** Click "Refresh Blockchain" (or wait for automatic updates) to see all blocks mined so far. You can inspect the details of each block, including its transactions.

## 6. Conceptual Deployment Notes

This application is a simplified demonstration and is not designed for production use without significant modifications. If you were to deploy a similar system for real-world use:

*   **Hosting:** You would host the Flask application on a server (e.g., using cloud providers like AWS, Google Cloud, Azure, or a VPS).
*   **Web Server:** Instead of Flask's built-in development server, a production-grade WSGI server like Gunicorn or uWSGI, often behind a reverse proxy like Nginx, would be used for performance, security, and scalability.
*   **Database:** The blockchain and wallet data (excluding private keys for user wallets) would typically be stored in a persistent database rather than in-memory lists for durability.
*   **Security:**
    *   **Private Key Management:** Users would manage their own private keys securely, never sending them to the server. Transactions would be signed client-side.
    *   **HTTPS:** Essential for encrypting communication.
    *   **Input Validation:** More robust input validation and sanitization would be needed.
    *   **Rate Limiting & DDoS Protection:** Measures to protect against abuse.
*   **Scalability:** For a large number of users and transactions, the current single-node architecture would need to be scaled, potentially involving distributed ledger technologies, more robust consensus mechanisms, and optimized data storage.
*   **Peer-to-Peer Networking:** A true blockchain involves a P2P network for block propagation and consensus, which is not implemented in this simplified example.
```
This `showcase_instructions.md` file provides a comprehensive guide for users to understand, set up, and interact with the blockchain application. It covers the core functionalities and offers insights into how a real-world system would differ.
The Flask app is now running in the background (PID 7574). I will now test the `/api/wallet/<address>/balance` endpoint for the current Satoshi address, including the debug trace.

Satoshi's address (obtained from the server log in the previous step): `30819f300d06092a864886f70d010101050003818d0030818902818100d72079b078443a20f4372c3869712463a91069423f9d19245271589d8133046611733892617249d40d38496818ac0890a7521f6b9107f49826d16296214669d828466d06e70699462008a1a18ed40873a805db16d961909c5018108f1f255f25530703363d3f5e17206663266e02745108a3671197d051c093a25d712a030203010001`
