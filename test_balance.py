```python
import subprocess
import time
import requests
import json
import os

from config import BLOCK_REWARD, MIN_TRANSACTION_FEE

# Ensure the script is run from the correct directory where app.py is located
script_dir = os.path.dirname(os.path.abspath(__file__))
os.chdir(script_dir)

print("Starting Flask server for testing...")
# Start the Flask app in the background
# Ensure PYTHONPATH is set if modules are in subdirectories, though here they are in app.py
env = os.environ.copy()
env["PYTHONUNBUFFERED"] = "1" # To see output immediately if needed for debugging server startup

# Kill any existing Flask server process
try:
    subprocess.run("pkill -f 'python app.py'", shell=True, check=False)
    time.sleep(1) # Give it a moment to shut down
except Exception as e:
    print(f"Error trying to kill existing process (may be normal if none was running): {e}")


server_process = subprocess.Popen(['python', 'app.py'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
print(f"Server started with PID {server_process.pid}")

# Give the server some time to initialize
time.sleep(7) # Increased sleep time to ensure server is fully up

satoshi_address = None
alice_address = None
bob_address = None

try:
    print("Fetching addresses from /api/get_addresses...")
    response = requests.get("http://localhost:5000/api/get_addresses", timeout=10)
    response.raise_for_status()
    addresses_data = response.json()
    satoshi_address = addresses_data.get("satoshi_address")
    alice_address = addresses_data.get("alice_address")
    bob_address = addresses_data.get("bob_address")
    print(f"Satoshi Address: {satoshi_address}")
    print(f"Alice Address: {alice_address}")
    print(f"Bob Address: {bob_address}")

    if not satoshi_address:
        print("Failed to retrieve Satoshi's address.")
    else:
        print(f"\nQuerying Satoshi's balance (address: {satoshi_address})...")
        balance_response = requests.get(f"http://localhost:5000/api/wallet/{satoshi_address}?debug=true", timeout=10)
        balance_response.raise_for_status()
        satoshi_balance_data = balance_response.json()
        print("\nSatoshi's Balance Response:")
        print(json.dumps(satoshi_balance_data, indent=2))

        # Verify Satoshi's balance
        expected_satoshi_balance = 40.0 - MIN_TRANSACTION_FEE # 25 (genesis) - 10 (to Alice) - 0.1 (fee) + 25 (block 1 reward) = 39.9
                                                        # Coinbase for Block 1 includes the fee, so MINER_WALLET gets BLOCK_REWARD + fee.
                                                        # Initial state: Satoshi gets 25 (Genesis).
                                                        # Tx: Satoshi sends 10 to Alice, fee 0.1. Inputs: 25. Outputs: 10 (Alice), 14.9 (Satoshi change).
                                                        # Block 1 mined by Satoshi: Coinbase (25 + 0.1 fee) = 25.1 to Satoshi.
                                                        # Satoshi's balance: 15 (change) + 25.1 (reward) = 40.1
        expected_satoshi_balance = BLOCK_REWARD - 10.0 - MIN_TRANSACTION_FEE + (BLOCK_REWARD + MIN_TRANSACTION_FEE) # 25 - 10 - 0.1 + (25 + 0.1) = 40.0
        
        if satoshi_balance_data.get("balance") == expected_satoshi_balance and satoshi_balance_data.get("debug_calculated_balance") == expected_satoshi_balance:
            print(f"\nSUCCESS: Satoshi's balance is correctly {expected_satoshi_balance}.")
        else:
            print(f"\nFAILURE: Satoshi's balance is {satoshi_balance_data.get('balance')}, expected {expected_satoshi_balance}.")
            print(f"Debug calculated balance: {satoshi_balance_data.get('debug_calculated_balance')}")


    if alice_address:
        print(f"\nQuerying Alice's balance (address: {alice_address})...")
        balance_response_alice = requests.get(f"http://localhost:5000/api/wallet/{alice_address}", timeout=10)
        balance_response_alice.raise_for_status()
        alice_balance_data = balance_response_alice.json()
        print("\nAlice's Balance Response:")
        print(json.dumps(alice_balance_data, indent=2))
        if alice_balance_data.get("balance") == 10.0:
             print(f"\nSUCCESS: Alice's balance is correctly 10.0.")
        else:
            print(f"\nFAILURE: Alice's balance is {alice_balance_data.get('balance')}, expected 10.0")


except requests.exceptions.RequestException as e:
    print(f"Error during HTTP request: {e}")
except json.JSONDecodeError as e:
    print(f"Error decoding JSON response: {e}")
except Exception as e:
    print(f"An unexpected error occurred: {e}")
finally:
    print(f"\nTerminating server with PID {server_process.pid}...")
    server_process.terminate()
    server_process.wait(timeout=5)
    if server_process.poll() is None: # Check if process is still running
        print(f"Server (PID {server_process.pid}) did not terminate, killing...")
        server_process.kill()
        server_process.wait()
    print("Server stopped.")

```

Now I will run this `test_balance.py` script.
This script should:
1. Create `utils.py`, `wallet.py`, `transaction.py`, `block.py` with the correct code from previous successful steps.
2. Create `app.py` with the Flask application and SocketIO integration.
3. Create `templates/index.html` and `static/app.js`.
4. Run `test_balance.py` which starts the Flask app, queries the API for Satoshi's and Alice's balances, and prints the results.
5. Submit the report.

I will first re-create all the necessary files to ensure they are in the correct state before running the test script.
