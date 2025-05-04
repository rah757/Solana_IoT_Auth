"""
admin_registry.py

Send `register:<pubkey>` or `revoke:<pubkey>` memos on Solana DevNet
using the Solana CLI.

Usage:
  python3 admin_registry.py register <pubkey>
  python3 admin_registry.py revoke   <pubkey>
"""

import sys
import subprocess
import json
import os
import base58
import tempfile

RPC_URL = "https://api.devnet.solana.com"
ADMIN_KEYPAIR = "admin_wallet.json"  # path to your admin keypair file
SOLANA_KEYPAIR = "solana_keypair.json"  # converted keypair file
AMOUNT = "0.00000001"

def usage():
    print(__doc__)
    sys.exit(1)

def ensure_solana_keypair():
    """Make sure we have a valid Solana keypair file"""
    
    # Check if the Solana keypair file exists
    if os.path.exists(SOLANA_KEYPAIR):
        return SOLANA_KEYPAIR
        
    # Otherwise, we need to convert admin_wallet.json
    if not os.path.exists(ADMIN_KEYPAIR):
        print(f"Error: Neither {SOLANA_KEYPAIR} nor {ADMIN_KEYPAIR} found")
        print(f"Please run 'python convert_wallet.py' first or ensure {ADMIN_KEYPAIR} exists")
        sys.exit(1)
    

    fd, temp_path = tempfile.mkstemp(suffix='.json')
    os.close(fd)
    
    try:
        # Read the admin wallet
        with open(ADMIN_KEYPAIR, 'r') as f:
            data = json.load(f)
        
        # Convert to Solana format
        if 'keypair' in data:
            keypair_b58 = data['keypair']
            keypair_bytes = base58.b58decode(keypair_b58)
            keypair_ints = [b for b in keypair_bytes]
            
            # Write as JSON array
            with open(temp_path, 'w') as f:
                json.dump(keypair_ints, f)
                
            return temp_path
        else:
            print(f"Error: {ADMIN_KEYPAIR} doesn't contain 'keypair' field")
            print("Please run 'python convert_wallet.py' first")
            sys.exit(1)
    except Exception as e:
        print(f"Error converting keypair: {e}")
        print("Please run 'python convert_wallet.py' first")
        sys.exit(1)

def get_public_key(keypair_path):
    """Get the public key for a keypair"""
    try:
        result = subprocess.run(
            ["solana", "address", "-k", keypair_path],
            capture_output=True,
            text=True,
            check=True
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        print(f"Error getting public key from keypair: {e}")
        print("Make sure your keypair file is valid and Solana CLI is installed")
        sys.exit(1)

def send_memo(action: str, pubkey: str):
    """Send a memo transaction on Solana"""
    # Ensure we have a valid keypair
    keypair_path = ensure_solana_keypair()
    
    try:
        sender_address = get_public_key(keypair_path)
        
        memo = f"{action}:{pubkey}"
        
        cmd = [
            "solana", "transfer",
            "--keypair", keypair_path,
            sender_address,  # Send to self
            AMOUNT,
            "--allow-unfunded-recipient",
            "--with-memo", memo,
            "--url", RPC_URL,
            "--skip-seed-phrase-validation",
        ]

        display_cmd = " ".join(cmd).replace(keypair_path, ADMIN_KEYPAIR)
        print("📡 Running:", display_cmd)
        
        subprocess.run(cmd, check=True)
        print(f"✅ Memo `{memo}` sent on DevNet")
    
    except subprocess.CalledProcessError as e:
        print(f"❌ Error sending memo: {e}")
        sys.exit(1)
        
    finally:
        if keypair_path != SOLANA_KEYPAIR and os.path.exists(keypair_path):
            os.unlink(keypair_path)

if __name__ == "__main__":
    if len(sys.argv) != 3 or sys.argv[1] not in ("register", "revoke"):
        usage()
    action, pub = sys.argv[1], sys.argv[2]
    send_memo(action, pub)