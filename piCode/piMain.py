"""
pi_node.py - Secure IoT authentication node using Solana blockchain (2-Device Mode)

This script implements a secure device authentication system using:
- Solana blockchain for message exchange
- On-chain challenges and responses
- NaCl for cryptographic operations
- Secure key exchange using curve25519

Usage (2-Device Mode):
  - Discover peer:   python node.py discover
  - Challenge peer:  python node.py challenge
  - Respond to peer: python node.py respond [PEER_PUBKEY] # Optional pubkey
  - Verify peer:     python node.py verify [PEER_PUBKEY]   # Optional pubkey
  - Establish Key:   python node.py establishkey [PEER_PUBKEY] # Generates NEW key, saves, sends. Optional pubkey. RECOMMENDED way to start.
  - Send Key (Rare): python node.py sendkey [PEER_PUBKEY]      # Sends *current* key file, if it exists. Optional pubkey.
  - Receive Key:     python node.py receivekey [PEER_PUBKEY]    # Optional pubkey. Waits for peer to send key.
  - Rotate Key:      python node.py rotatekey [PEER_PUBKEY]     # Generates/sends new key, replaces old. Optional pubkey.
  - Check Auth:      python node.py checkauth                 # Checks if device is revoked by admin.
  - Send message:    python node.py send [MESSAGE]             # Sends to the other device using established key.
  - Poll messages:   python node.py poll                    # Polls the other device using established key.
  - Start Session:   python node.py startsession [PEER_PUBKEY] # Clears state, establishes new key. Optional pubkey.
"""

import json
import base58
import time
import os
import sys
from datetime import datetime
import base64 
import hashlib 
import requests 
import traceback 


from solders.keypair import Keypair
from solders.pubkey import Pubkey
from solders.transaction import Transaction
from solders.instruction import Instruction, AccountMeta
from solders.message import Message
from solders.hash import Hash
from solana.rpc.api import Client
from solana.exceptions import SolanaRpcException


from nacl.secret import SecretBox
from nacl.public import PrivateKey as CurvePrivateKey, PublicKey as CurvePublicKey, SealedBox
from nacl.utils import random as rand
from nacl.exceptions import CryptoError
from nacl.signing import SigningKey, VerifyKey

RPC_URL = "https://api.devnet.solana.com"  # Using Devnet
WALLET = "wallet.json"                     # Local device keypair
MEMO_PID = Pubkey.from_string("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr")
MEMO_PID_STR = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr" # String version
CHALLENGE_FILE = "challenge.txt"           # Stores sent challenge nonce
SYM_KEY_FILE = "sym_key.bin"               # Stores the shared symmetric key
SEEN_SIGNATURES_FILE = "seen_signatures.json" # Stores sigs of processed msgs
SESSION_FILE = "session.json"              # Stores current session info
ADMIN_PUBKEY = "A258nzaphJAAFTkYqHwH4ax9KcxaHCQ7VqRTRxVBoq1A" # Pubkey of admin sending register/revoke memos
POLLING_INTERVAL = 5                       # seconds between polls
GET_TX_LIMIT = 25                          # How many tx sigs to check for key/msgs
DEBUG_MODE = True                          # Enable debug logging

# --- Logging ---
def log(message, level="INFO"):
    """Print log messages with timestamp"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] {level}: {message}")

def debug(message):
    """Print debug messages if debug mode is enabled"""
    if DEBUG_MODE:
        log(message, "DEBUG")

# --- Key Loading ---
def load_keypair() -> Keypair:
    """Load ed25519 keypair from wallet file"""
    try:
        with open(WALLET, 'r') as f:
            wallet_data = json.load(f)
        if "keypair" not in wallet_data:
            raise ValueError("Wallet missing 'keypair' field")
        raw = base58.b58decode(wallet_data["keypair"])
        kp = Keypair.from_bytes(raw)
        if len(bytes(kp)) != 64:
             raise ValueError(f"Decoded keypair has incorrect size: {len(bytes(kp))}")
        debug(f"Keypair loaded successfully from {WALLET}. Pubkey: {kp.pubkey()}")
        return kp
    except FileNotFoundError:
        log(f"Wallet file '{WALLET}' not found.", "ERROR")
        raise
    except Exception as e:
        log(f"Failed to load keypair from {WALLET}: {e}", "ERROR")
        raise

# --- Authorization Check ---
def check_authorization() -> bool:
    """
    Check if this device is still authorized by the admin by scanning admin transactions.
    Returns True if authorized or status unknown, False if explicitly revoked.
    """
    try:
        own_keypair = load_keypair()
        own_pubkey = str(own_keypair.pubkey())
        debug(f"Checking authorization for device: {own_pubkey[:10]}...")

        client = Client(RPC_URL)
        admin_pubkey_obj = Pubkey.from_string(ADMIN_PUBKEY)

        signatures_resp = client.get_signatures_for_address(admin_pubkey_obj, limit=100)
        if not hasattr(signatures_resp, 'value') or not signatures_resp.value:
            log("No admin transactions found to check authorization status.", "WARNING")
            return True # Assume authorized if unable to check

        # Process admin transactions, newest first determines final status
        status = None # None = unknown, True = registered, False = revoked
        processed_count = 0
        for sig_info in reversed(signatures_resp.value): # Newest first
             signature = str(sig_info.signature)
             processed_count += 1
             debug(f"Checking admin tx {processed_count}/{len(signatures_resp.value)} for auth: {signature[:10]}...")

             # Use requests for getTransaction
             payload = {
                 "jsonrpc": "2.0", "id": 1, "method": "getTransaction",
                 "params": [ signature, {"encoding": "json", "maxSupportedTransactionVersion": 0} ]
             }
             try:
                 response = requests.post(RPC_URL, json=payload, timeout=10)
                 if response.status_code == 429: time.sleep(1); response = requests.post(RPC_URL, json=payload, timeout=10) # retry
                 response.raise_for_status()
                 result = response.json()
                 if 'error' in result: continue # Skip on RPC error
                 if 'result' not in result or not result['result']: continue
                 tx_data = result['result']
             except Exception as fetch_err:
                  log(f"Error fetching/parsing admin tx {signature[:10]} for auth check: {fetch_err}", "WARNING")
                  time.sleep(0.1); continue # Skip on fetch error

             if tx_data and 'meta' in tx_data and tx_data['meta'] and 'logMessages' in tx_data['meta']:
                 logs = tx_data['meta']['logMessages']
                 if not logs: continue
                 status_found_in_this_tx = False
                 for log_msg in logs:
                     if isinstance(log_msg, str) and "Program log: Memo" in log_msg:
                         # Improved check for register/revoke memos for this device
                         register_pattern_quoted = f'"register:{own_pubkey}"'
                         register_pattern_unquoted = f'register:{own_pubkey}'
                         revoke_pattern_quoted = f'"revoke:{own_pubkey}"'
                         revoke_pattern_unquoted = f'revoke:{own_pubkey}'

                         # Check if the exact pattern exists
                         if register_pattern_quoted in log_msg or log_msg.strip().endswith(register_pattern_unquoted):
                             log(f"Found registration memo for this device in tx {signature[:10]}", "DEBUG")
                             status = True
                             status_found_in_this_tx = True
                             break
                         elif revoke_pattern_quoted in log_msg or log_msg.strip().endswith(revoke_pattern_unquoted):
                             log(f"Found revocation memo for this device in tx {signature[:10]}", "WARNING")
                             status = False
                             status_found_in_this_tx = True
                             break
                 if status_found_in_this_tx:
                      break
             time.sleep(0.05)

        if status is False: log("Authorization check result: Device REVOKED by admin.", "ERROR"); return False
        elif status is True: log("Authorization check result: Device is REGISTERED.", "INFO"); return True
        else: log("Authorization check result: Status UNKNOWN. Assuming authorized.", "WARNING"); return True

    except Exception as e:
        log(f"Error checking authorization: {e}", "WARNING"); log(traceback.format_exc(), "DEBUG"); return True

# --- Symmetric Key Management ---
def load_sym_key() -> bytes:
    """Load symmetric key from file. Raise error if missing or invalid."""
    sym_key_path = SYM_KEY_FILE
    expected_size = SecretBox.KEY_SIZE

    if not os.path.exists(sym_key_path):
        raise FileNotFoundError(f"Symmetric key file '{sym_key_path}' not found. Run 'establishkey' or 'receivekey' first.")

    try:
        with open(sym_key_path, "rb") as f: key_data = f.read()
        if len(key_data) != expected_size: raise ValueError(f"Invalid key size in {sym_key_path}. Expected {expected_size}, got {len(key_data)}")
        debug(f"Loaded symmetric key, length: {len(key_data)}")
        return key_data
    except Exception as e: log(f"Failed to load symmetric key from {sym_key_path}: {e}", "ERROR"); raise

# --- Solana Interaction ---
def post_memo(text: str):
    """Post a memo to the blockchain"""
    try:
        kp = load_keypair()
        account = AccountMeta(pubkey=kp.pubkey(), is_signer=True, is_writable=False)
        ix = Instruction(program_id=MEMO_PID, accounts=[account], data=text.encode('utf-8'))
        client = Client(RPC_URL)
        blockhash_resp = client.get_latest_blockhash()
        blockhash = blockhash_resp.value.blockhash
        message = Message.new_with_blockhash([ix], kp.pubkey(), blockhash)
        tx = Transaction.new_unsigned(message); tx.sign([kp], blockhash)

        log(f"Posting memo: {text[:30]}{'...' if len(text) > 30 else ''}")
        resp = client.send_raw_transaction(bytes(tx))

        if hasattr(resp, 'value') and resp.value: signature = resp.value; log(f"Memo posted, signature: {signature}"); return signature
        else: log(f"Memo post did not return a signature. Response: {resp}", "ERROR"); return None
    except SolanaRpcException as rpc_err: log(f"Solana RPC Error posting memo: {rpc_err}", "ERROR"); return None
    except Exception as e: log(f"Failed to post memo: {e}", "ERROR"); log(traceback.format_exc(), "DEBUG"); return None

# --- Core Logic Functions ---
def post_challenge():
    """Create and post a challenge nonce"""
    if not check_authorization(): log("Cannot issue challenge: Device revoked", "ERROR"); return None
    try:
        nonce = hex(int(time.time() * 1000))[2:] + hex(int.from_bytes(os.urandom(4), 'big'))[2:]
        sig = post_memo(f"challenge:{nonce}")
        if not sig: return None
        with open(CHALLENGE_FILE, "w") as f: f.write(nonce)
        log(f"Challenge posted: {nonce}, signature: {sig}")
        return nonce
    except Exception as e: log(f"Failed to post challenge: {e}", "ERROR"); return None

def respond_to_challenge(peer_pub):
    """Respond to a challenge - simplified (No key generation)"""
    if not check_authorization(): log("Cannot respond: Device revoked", "ERROR"); return False
    try:
        sig = post_memo(f"respond:{peer_pub}")
        if sig: log(f"Response sent, signature: {sig}"); return True
        else: log(f"Failed to post response memo.", "ERROR"); return False
    except Exception as e: log(f"Failed to respond: {e}", "ERROR"); return False

def verify_response(peer_pub):
    """Verify a response - simplified (No key generation)"""
    if not check_authorization(): log("Cannot verify: Device revoked", "ERROR"); return False
    try:
        log(f"Verification attempted for peer: {peer_pub}")
        if os.path.exists(SYM_KEY_FILE): log("Symmetric key file exists.")
        else: log("Symmetric key file does not exist yet. Needs key exchange.", "WARNING")
        return True # Placeholder
    except Exception as e: log(f"Verification failed: {e}", "ERROR"); return False

def discover_devices() -> dict:
    """
    Discover registered devices by scanning admin registration memos,
    excluding the current device's own wallet address.
    Returns: dict {pubkey_str: status_str}
    """
    devices = {}
    try:
        log("Discovering registered devices...")
        client = Client(RPC_URL)
        own_keypair = load_keypair()
        own_pubkey = str(own_keypair.pubkey())
        log(f"Own public key: {own_pubkey[:10]}...{own_pubkey[-5:]}")

        admin_pubkey_obj = Pubkey.from_string(ADMIN_PUBKEY)
        log(f"Scanning transactions from admin: {ADMIN_PUBKEY[:10]}...")

        signatures_resp = client.get_signatures_for_address(admin_pubkey_obj, limit=100)
        if not hasattr(signatures_resp, 'value') or not signatures_resp.value:
            log("No transactions found for admin wallet.", "WARNING"); return devices

        log(f"Found {len(signatures_resp.value)} admin transactions to scan.")
        processed_count = 0
        for sig_info in reversed(signatures_resp.value): # Process newest first
            signature = str(sig_info.signature); processed_count += 1
            debug(f"Processing admin tx {processed_count}/{len(signatures_resp.value)}: {signature[:10]}...")

            payload = { "jsonrpc": "2.0", "id": 1, "method": "getTransaction", "params": [ signature, {"encoding": "json", "maxSupportedTransactionVersion": 0} ] }
            try:
                response = requests.post(RPC_URL, json=payload, timeout=10)
                if response.status_code == 429: time.sleep(1); response = requests.post(RPC_URL, json=payload, timeout=10)
                response.raise_for_status(); result = response.json()
                if 'error' in result: continue
                if 'result' not in result or not result['result']: continue
                tx_data = result['result']
            except Exception as fetch_err: log(f"Error fetching/parsing admin tx {signature[:10]}: {fetch_err}", "WARNING"); time.sleep(0.2); continue

            if tx_data and 'meta' in tx_data and tx_data['meta'] and 'logMessages' in tx_data['meta']:
                logs = tx_data['meta']['logMessages']
                if not logs: continue
                for log_msg in logs:
                    if isinstance(log_msg, str) and "Program log: Memo" in log_msg:
                        try:
                            action = None; key_start = -1; pubkey = None

                            if '"register:' in log_msg:
                                action = "registered"; key_start = log_msg.find('"register:') + 10
                                end_idx = log_msg.find('"', key_start)
                                if end_idx != -1: pubkey = log_msg[key_start:end_idx]
                            elif '"revoke:' in log_msg:
                                action = "revoked"; key_start = log_msg.find('"revoke:') + 8
                                end_idx = log_msg.find('"', key_start)
                                if end_idx != -1: pubkey = log_msg[key_start:end_idx]
                            elif "register:" in log_msg:
                                action = "registered"
                                key_start = log_msg.find("register:") + 9
                                end_char_idx = len(log_msg)
                                for char in [' ', '\n', '\r', '\t', '"']:
                                     space_idx = log_msg.find(char, key_start)
                                     if space_idx != -1: end_char_idx = min(end_char_idx, space_idx)
                                pubkey = log_msg[key_start:end_char_idx]
                            elif "revoke:" in log_msg:
                                action = "revoked"
                                key_start = log_msg.find("revoke:") + 7
                                end_char_idx = len(log_msg)
                                for char in [' ', '\n', '\r', '\t', '"']:
                                     space_idx = log_msg.find(char, key_start)
                                     if space_idx != -1: end_char_idx = min(end_char_idx, space_idx)
                                pubkey = log_msg[key_start:end_char_idx]

                            if action and pubkey:
                                pubkey = pubkey.strip()
                                is_valid_pubkey = False
                                try: # Validate format
                                    decoded_bytes = base58.b58decode(pubkey)
                                    if len(decoded_bytes) == 32: is_valid_pubkey = True
                                except ValueError: debug(f"Invalid base58 characters during validation: '{pubkey}'")
                                except Exception: pass

                                if is_valid_pubkey:
                                    if pubkey == own_pubkey: debug(f"Skipping own device reg memo: {pubkey[:10]}..."); continue
                                    if pubkey not in devices or devices[pubkey] == "revoked" or action == "revoked":
                                        devices[pubkey] = action; log(f"Found device: {pubkey[:10]}... ({action})")
                                else: debug(f"Skipping invalid pubkey format/length after extraction: '{pubkey}'")
                        except Exception as parse_err: log(f"Error parsing admin memo log: {parse_err}", "WARNING")
            time.sleep(0.05)

        registered_devices = {k: v for k, v in devices.items() if v == "registered"}
        log(f"Discovery finished. Found {len(registered_devices)} registered devices (excluding self).")
        return registered_devices
    except Exception as e: log(f"Error during device discovery: {e}", "ERROR"); log(traceback.format_exc(), "DEBUG"); return {}


# --- Key Exchange Functions ---
def establish_key(peer_pub: str) -> bool:
    """Generates a NEW symmetric key, saves it locally, and sends it to the peer."""
    if not check_authorization(): log("Cannot establish key: Device revoked", "ERROR"); return False
    try:
        log(f"Establishing new symmetric key for communication with {peer_pub[:10]}...")
        new_sym_key = rand(SecretBox.KEY_SIZE)
        log(f"Generated new symmetric key, length: {len(new_sym_key)}")
        with open(SYM_KEY_FILE, "wb") as f: f.write(new_sym_key)
        log(f"New symmetric key saved locally to {SYM_KEY_FILE}")

        if send_key(peer_pub):
             log("Successfully established and shared new symmetric key")
             return True
        else:
             log("Failed to send the new symmetric key to peer", "ERROR")
             try:
                 os.remove(SYM_KEY_FILE)
                 log("Cleaned up unsent key file.", "DEBUG")
             except OSError:
                 log("Failed to clean up unsent key file.", "WARNING")
             return False
    except Exception as e:
        log(f"Failed to establish key: {e}", "ERROR"); log(traceback.format_exc(), "DEBUG"); return False

def send_key(peer_pub: str, key_file=None) -> bool:
    """Sends the symmetric key (from key_file or default) encrypted to the peer."""
    if not check_authorization(): log("Cannot send key: Device revoked", "ERROR"); return False
    try:
        key_path = key_file or SYM_KEY_FILE
        log(f"Attempting to send symmetric key from {key_path} to: {peer_pub[:10]}...")
        if not os.path.exists(key_path): raise FileNotFoundError(f"Key file '{key_path}' not found.")
        with open(key_path, "rb") as f: sym_key = f.read()
        if len(sym_key) != SecretBox.KEY_SIZE: raise ValueError(f"Invalid key size in {key_path}.")
        log(f"Loaded symmetric key from {key_path}, length: {len(sym_key)}")

        try: peer_ed_pubkey_bytes = base58.b58decode(peer_pub); peer_curve_public_key = VerifyKey(peer_ed_pubkey_bytes).to_curve25519_public_key()
        except Exception as e: log(f"Failed to convert peer pubkey {peer_pub[:10]}: {e}", "ERROR"); return False

        try: box = SealedBox(peer_curve_public_key); encrypted = box.encrypt(sym_key); encoded = base58.b58encode(encrypted).decode('ascii'); sig = post_memo(f"nacl_curve:{encoded}")
        except Exception as e: log(f"Failed during encryption/sending of key: {e}", "ERROR"); return False

        if sig: log(f"✅ Symmetric key sent successfully! Signature: {sig}"); return True
        else: log("Failed to post memo for symmetric key.", "ERROR"); return False
    except (FileNotFoundError, ValueError) as key_err: log(f"Cannot send key: {key_err}", "ERROR"); return False
    except Exception as e: log(f"Failed to send key: {e}", "ERROR"); log(traceback.format_exc(), "DEBUG"); return False

def receive_key(peer_pub: str) -> bool:
    """Receives and decrypts a symmetric key, saving it."""
    if not check_authorization(): log("Cannot receive key: Device revoked", "ERROR"); return False
    try:
        log(f"Looking for symmetric key sent by peer: {peer_pub[:10]}...")
        kp = load_keypair()
        try: kp_bytes = bytes(kp); ed_signing_key = SigningKey(seed=kp_bytes[:32]); my_curve_private_key = ed_signing_key.to_curve25519_private_key(); log(f"Own key converted for decryption.")
        except Exception as e: log(f"Failed to convert own keypair: {e}", "ERROR"); return False

        client = Client(RPC_URL)
        try: peer_pubkey_obj = Pubkey.from_string(peer_pub)
        except ValueError: log(f"Invalid peer pubkey format: {peer_pub}", "ERROR"); return False

        log(f"Fetching transactions sent BY {peer_pub[:10]}...")
        signatures_resp = client.get_signatures_for_address(peer_pubkey_obj, limit=GET_TX_LIMIT)
        if not hasattr(signatures_resp, 'value') or not signatures_resp.value: log(f"No transactions found from peer {peer_pub[:10]}...", "WARNING"); return False
        log(f"Found {len(signatures_resp.value)} transactions from {peer_pub[:10]}... to check for key")

        processed_key = False; processed_count = 0
        for sig_info in reversed(signatures_resp.value):
            if processed_key: break
            signature = str(sig_info.signature); processed_count += 1; debug(f"Checking peer tx {processed_count}/{len(signatures_resp.value)}: {signature[:10]}...")

            payload = { "jsonrpc": "2.0", "id": 1, "method": "getTransaction", "params": [ signature, {"encoding": "json", "maxSupportedTransactionVersion": 0} ] }
            try:
                response = requests.post(RPC_URL, json=payload, timeout=10)
                if response.status_code == 429: time.sleep(1); response = requests.post(RPC_URL, json=payload, timeout=10)
                response.raise_for_status(); result = response.json()
                if 'error' in result: continue
                if 'result' not in result or not result['result']: continue
                tx_data = result['result']
            except Exception as fetch_err: log(f"Error fetching/parsing peer tx {signature[:10]}: {fetch_err}", "WARNING"); time.sleep(0.2); continue

            if tx_data and 'meta' in tx_data and tx_data['meta'] and 'logMessages' in tx_data['meta']:
                logs = tx_data['meta']['logMessages']
                if not logs: continue
                for log_msg in logs:
                    prefix = '"nacl_curve:'
                    if isinstance(log_msg, str) and "Program log: Memo" in log_msg and prefix in log_msg:
                        log(f"Found potential key memo in tx {signature[:10]}...: {log_msg[:60]}...")
                        try:
                            parts = log_msg.split(prefix, 1)
                            if len(parts) == 2: encoded_part = parts[1]; end_quote_idx = encoded_part.rfind('"'); encoded = encoded_part[:end_quote_idx] if end_quote_idx != -1 else None
                            else: continue
                            if not encoded: log("Malformed key memo log.", "WARNING"); continue

                            encrypted = base58.b58decode(encoded)
                            box = SealedBox(my_curve_private_key)
                            sym_key = box.decrypt(encrypted)
                            if len(sym_key) != SecretBox.KEY_SIZE: log(f"Decrypted key wrong size ({len(sym_key)}). Skipping.", "WARNING"); continue

                            with open(SYM_KEY_FILE, "wb") as f: f.write(sym_key)
                            log(f"✅ Symmetric key received, decrypted, and saved! Length: {len(sym_key)}")
                            processed_key = True; return True # Success
                        except ValueError: log(f"Invalid base58 key data in {signature[:10]}", "WARNING")
                        except CryptoError: log(f"Decryption failed (CryptoError) for key in {signature[:10]}. Not for us?", "DEBUG")
                        except Exception as e: log(f"Error decoding/decrypting key data in {signature[:10]}: {e}", "ERROR"); log(traceback.format_exc(), "DEBUG")
            if processed_key: break
            time.sleep(0.05)

        if not processed_key: log("No valid symmetric key found in recent transactions from peer.", "WARNING")
        return False
    except Exception as e: log(f"Unexpected error in receive_key: {e}", "ERROR"); log(traceback.format_exc(), "DEBUG"); return False

def rotate_key(peer_pub: str) -> bool:
    """Generates a new symmetric key, sends it, and replaces the old one."""
    if not check_authorization(): log("Cannot rotate key: Device revoked", "ERROR"); return False
    try:
        log(f"Rotating symmetric key for communication with {peer_pub[:10]}...")
        if not os.path.exists(SYM_KEY_FILE): log("No existing key found. Use 'establishkey'.", "ERROR"); return False

        new_key = rand(SecretBox.KEY_SIZE)
        log(f"Generated new symmetric key, length: {len(new_key)}")
        temp_key_file = SYM_KEY_FILE + ".new"
        with open(temp_key_file, "wb") as f: f.write(new_key)

        success = send_key(peer_pub, key_file=temp_key_file) # Send the new key

        if success:
            backup_file = SYM_KEY_FILE + ".backup"
            try: # Backup old key
                if os.path.exists(backup_file): os.remove(backup_file)
                os.rename(SYM_KEY_FILE, backup_file)
            except OSError as e: log(f"Error backing up old key: {e}", "WARNING")
            try: # Activate new key
                os.rename(temp_key_file, SYM_KEY_FILE)
                log("Successfully rotated symmetric key.")
                return True
            except OSError as e: # Failed to activate new key, try to restore backup
                log(f"CRITICAL: Failed to activate new key: {e}. Attempting restore.", "ERROR")
                try: os.rename(backup_file, SYM_KEY_FILE)
                except OSError as restore_e: log(f"CRITICAL: Failed to restore backup key: {restore_e}", "ERROR")
                return False
        else: # Sending failed
            log("Failed to send the new symmetric key to peer. Rotation aborted.", "ERROR")
            try: os.remove(temp_key_file) # Clean up temp file
            except OSError: pass
            return False
    except Exception as e: log(f"Failed to rotate key: {e}", "ERROR"); log(traceback.format_exc(), "DEBUG"); return False

# --- Session Management ---
def load_session() -> dict | None:
    """Loads session data from file."""
    if os.path.exists(SESSION_FILE):
        try:
            with open(SESSION_FILE, "r") as f: return json.load(f)
        except Exception as e: log(f"Error loading session file: {e}", "WARNING")
    return None

def save_session(session_data: dict):
    """Saves session data to file."""
    try:
        with open(SESSION_FILE, "w") as f: json.dump(session_data, f, indent=2)
    except Exception as e: log(f"Error saving session file: {e}", "WARNING")

def start_session(peer_pub: str) -> bool:
    """Starts a new secure session: clears state, establishes new key."""
    if not check_authorization(): log("Cannot start session: Device revoked", "ERROR"); return False
    try:
        log(f"Starting new secure session with {peer_pub[:10]}...")
        # Backup existing key if any
        if os.path.exists(SYM_KEY_FILE):
            backup_file = SYM_KEY_FILE + ".backup"; log("Backing up existing symmetric key...")
            try:
                if os.path.exists(backup_file): os.remove(backup_file)
                os.rename(SYM_KEY_FILE, backup_file)
            except OSError as e: log(f"Could not backup existing key: {e}", "WARNING")

        # Clear seen signatures
        if os.path.exists(SEEN_SIGNATURES_FILE):
             try: os.remove(SEEN_SIGNATURES_FILE)
             except OSError as e: log(f"Could not clear seen signatures file: {e}", "WARNING")

        session_data = {"peer": peer_pub, "started": int(time.time()), "status": "initializing"}; save_session(session_data)
        success = establish_key(peer_pub) # Establish a new key

        if success:
            session_data["status"] = "active"; save_session(session_data)
            log("New secure session started successfully."); return True
        else: # Key establishment failed
            session_data["status"] = "failed"; save_session(session_data)
            log("Failed to establish key for new session.", "ERROR")
            if os.path.exists(SYM_KEY_FILE + ".backup"): # Try to restore backup key
                 try: os.rename(SYM_KEY_FILE + ".backup", SYM_KEY_FILE); log("Restored previous key.")
                 except OSError as e: log(f"Failed to restore backup key: {e}", "ERROR")
            return False
    except Exception as e: log(f"Failed to start session: {e}", "ERROR"); log(traceback.format_exc(), "DEBUG"); return False

# --- Persistence for Polling ---
def load_seen_signatures() -> set:
    """Load set of seen message signatures"""
    if os.path.exists(SEEN_SIGNATURES_FILE):
        try:
            with open(SEEN_SIGNATURES_FILE, "r") as f: return set(json.load(f))
        except Exception as e: log(f"Error loading seen signatures: {e}", "WARNING")
    return set()

def save_seen_signatures(signatures: set):
    """Save set of seen message signatures"""
    try:
        with open(SEEN_SIGNATURES_FILE, "w") as f: json.dump(list(signatures), f)
    except Exception as e: log(f"Error saving seen signatures: {e}", "WARNING")

# --- Messaging Functions ---
def send_message(text: str) -> bool:
    """Send an encrypted message using the shared symmetric key (With Nonce)."""
    if not check_authorization(): log("Cannot send message: Device revoked", "ERROR"); return False
    try:
        sym_key = load_sym_key() # Raises error if key missing/invalid
        message_data = { "text": text, "timestamp": int(time.time()), "sender": str(load_keypair().pubkey()) }
        message_json = json.dumps(message_data).encode('utf-8')

        box = SecretBox(sym_key); nonce = rand(SecretBox.NONCE_SIZE)
        encrypted_bytes = box.encrypt(message_json, nonce)
        full_payload = nonce + encrypted_bytes.ciphertext
        ciphertext_b58 = base58.b58encode(full_payload).decode('ascii')

        sig = post_memo(f"msg:{ciphertext_b58}")
        if sig: log(f"Encrypted message sent, signature: {sig}"); return True
        else: log("Failed to post message memo.", "ERROR"); return False
    except (FileNotFoundError, ValueError) as key_err: log(f"Cannot send message: {key_err}", "ERROR"); return False
    except Exception as e: log(f"Failed to send message: {e}", "ERROR"); log(traceback.format_exc(), "DEBUG"); return False

def poll_messages(peer_pub: str):
    """Poll for messages from peer and decrypt using the shared symmetric key (With Nonce)."""
    if not check_authorization(): log("Cannot poll messages: Device revoked", "ERROR"); return

    try: sym_key = load_sym_key(); log("Symmetric key loaded successfully for polling.")
    except (FileNotFoundError, ValueError) as key_err: log(f"Cannot poll messages: {key_err}", "ERROR"); return

    try: # Main polling loop
        client = Client(RPC_URL); peer_pubkey_obj = Pubkey.from_string(peer_pub)
        seen_signatures = load_seen_signatures(); last_displayed_signature = None
        log(f"Starting to poll for messages from {peer_pub[:10]}..."); log("Press Ctrl+C to stop polling.")

        while True:
            try:
                signatures_resp = client.get_signatures_for_address(peer_pubkey_obj, limit=10)
                if not hasattr(signatures_resp, 'value') or not signatures_resp.value: time.sleep(POLLING_INTERVAL); continue

                new_signatures_info = [sig for sig in signatures_resp.value if str(sig.signature) not in seen_signatures]
                if new_signatures_info: debug(f"Found {len(new_signatures_info)} new transaction(s) from peer.")

                for sig_info in reversed(new_signatures_info):
                    signature = str(sig_info.signature); seen_signatures.add(signature)
                    debug(f"Checking peer tx {signature[:10]} for messages...")

                    payload = { "jsonrpc": "2.0", "id": 1, "method": "getTransaction", "params": [ signature, {"encoding": "json", "maxSupportedTransactionVersion": 0} ] }
                    try:
                        response = requests.post(RPC_URL, json=payload, timeout=10)
                        if response.status_code == 429: time.sleep(1); response = requests.post(RPC_URL, json=payload, timeout=10)
                        response.raise_for_status(); result = response.json()
                        if 'error' in result: continue
                        if 'result' not in result or not result['result']: continue
                        tx_data = result['result']
                    except Exception as fetch_err: log(f"Error fetching/parsing peer tx {signature[:10]}: {fetch_err}", "WARNING"); time.sleep(0.2); continue

                    if tx_data and 'meta' in tx_data and tx_data['meta'] and 'logMessages' in tx_data['meta']:
                        logs = tx_data['meta']['logMessages']
                        if not logs: continue
                        for log_msg in logs:
                            prefix = '"msg:'
                            if isinstance(log_msg, str) and "Program log: Memo" in log_msg and prefix in log_msg:
                                try:
                                    parts = log_msg.split(prefix, 1)
                                    if len(parts) == 2: encoded_part = parts[1]; end_quote_idx = encoded_part.rfind('"'); encoded = encoded_part[:end_quote_idx] if end_quote_idx != -1 else None
                                    else: continue
                                    if not encoded: log("Malformed msg memo log.", "WARNING"); continue

                                    full_payload = base58.b58decode(encoded) # Decode base58 (nonce + ciphertext)
                                    nonce_size = SecretBox.NONCE_SIZE # Extract nonce and ciphertext
                                    if len(full_payload) <= nonce_size: log(f"Msg payload too short in {signature[:10]}", "WARNING"); continue
                                    nonce = full_payload[:nonce_size]; ciphertext = full_payload[nonce_size:]

                                    box = SecretBox(sym_key) # Decrypt
                                    plaintext_bytes = box.decrypt(ciphertext, nonce)
                                    plaintext_json = plaintext_bytes.decode('utf-8')

                                    message_data = json.loads(plaintext_json) # Parse JSON
                                    text = message_data.get("text", "(no text)")
                                    timestamp = message_data.get("timestamp", 0)
                                    sender = message_data.get("sender", "unknown")
                                    time_str = datetime.fromtimestamp(timestamp).strftime('%H:%M:%S') if timestamp else "??:??:??"

                                    if signature != last_displayed_signature: # Display if new
                                         sender_short = sender[:8] + "..." + sender[-4:] if len(sender) > 12 else sender
                                         print(f"[{time_str}] 📩 {sender_short}: {text}")
                                         last_displayed_signature = signature

                                except ValueError: log(f"Invalid base58 or other value error in {signature[:10]}", "WARNING") 
                                except CryptoError: log(f"Decryption failed for msg in {signature[:10]} (CryptoError). Wrong key/peer?", "DEBUG")
                                except UnicodeDecodeError: log(f"Failed to decode decrypted message in {signature[:10]} as UTF-8.", "WARNING")
                                except json.JSONDecodeError: log(f"Failed to parse message JSON in {signature[:10]}", "WARNING") 
                                except Exception as e: log(f"Error processing message in {signature[:10]}: {e}", "ERROR"); log(traceback.format_exc(), "DEBUG")
                    time.sleep(0.05)

                save_seen_signatures(seen_signatures); time.sleep(POLLING_INTERVAL)

            except KeyboardInterrupt: log("Polling stopped by user."); save_seen_signatures(seen_signatures); return
            except SolanaRpcException as rpc_err: log(f"Solana RPC Error during polling: {rpc_err}", "WARNING"); time.sleep(POLLING_INTERVAL * 2)
            except Exception as e: log(f"Error during polling loop: {e}", "WARNING"); log(traceback.format_exc(), "DEBUG"); time.sleep(POLLING_INTERVAL)

    except Exception as outer_e: log(f"Failed to start polling: {outer_e}", "ERROR"); log(traceback.format_exc(), "DEBUG")


# --- Main Execution Logic  ---
def main():
    """Main entry point"""
    if len(sys.argv) < 2:
        print(__doc__)
        return 1

    command = sys.argv[1].lower()

    try:
        if command == "checkauth":
            if check_authorization(): print("✅ This device is currently authorized"); return 0
            else: print("❌ This device has been revoked by the admin"); return 1


        peer_commands_optional_arg = ["respond", "verify", "sendkey", "receivekey",
                                      "establishkey", "rotatekey", "startsession"]

        if command in peer_commands_optional_arg:
            peer_pubkey = None
            if len(sys.argv) >= 3:
                 peer_pubkey = sys.argv[2]
                 print(f"Using specified peer: {peer_pubkey[:10]}...")
            else:
                 print(f"No peer specified for '{command}', discovering the other device...")
                 devices = discover_devices()
                 if not devices:
                     print(f"Error: Cannot find the other registered device to perform '{command}'.")
                     print(f"Usage: python node.py {command} [PEER_PUBKEY]")
                     return 1
                 if len(devices) > 1: log(f"Warning: Discovered multiple ({len(devices)}) devices. Using first.", "WARNING")
                 peer_pubkey = next(iter(devices.keys()))
                 print(f"Automatically targeting the other device: {peer_pubkey[:10]}...")


            success = False
            if command == "respond": success = respond_to_challenge(peer_pubkey)
            elif command == "verify": success = verify_response(peer_pubkey)
            elif command == "sendkey": success = send_key(peer_pubkey)
            elif command == "receivekey": success = receive_key(peer_pubkey)
            elif command == "establishkey": success = establish_key(peer_pubkey)
            elif command == "rotatekey": success = rotate_key(peer_pubkey)
            elif command == "startsession": success = start_session(peer_pubkey)

            if not success: return 1 # Return error code if function failed


        elif command == "discover":
            devices = discover_devices()
            if devices:
                print("\nRegistered Devices:")
                other_device_pubkey = next(iter(devices.keys()))
                status = devices[other_device_pubkey]
                print(f"  {other_device_pubkey} ({status})")
            else:
                print("No other registered devices found.")

        elif command == "challenge":
            post_challenge()

        elif command == "send":
            if len(sys.argv) < 3: print("Error: Missing message text\nUsage: python node.py send [MESSAGE]"); return 1
            message = " ".join(sys.argv[2:])
            if not message: print("Error: Message text cannot be empty"); return 1

            print("Discovering peer to send message to...")
            devices = discover_devices()
            if not devices: print("Error: Cannot find the other registered device to send to."); return 1
            target_peer = next(iter(devices.keys()))

            print(f"Sending message: '{message}' (intended for {target_peer[:10]}...)")
            if not send_message(message): print("Message send failed (check logs)."); return 1
            else: print("Message send initiated successfully.")


        elif command == "poll":
            print("Discovering peer to poll...")
            devices = discover_devices()
            if not devices: print("Error: Cannot find the other registered device to poll."); return 1
            peer_pubkey = next(iter(devices.keys()))
            print(f"Polling messages from: {peer_pubkey[:10]}...")
            poll_messages(peer_pubkey)

        else:
            print(f"Unknown command: {command}")
            print(__doc__)
            return 1

    except FileNotFoundError as fnf_err:
         log(f"Initialization or command failed: {fnf_err}", "ERROR")
         return 1
    except ValueError as val_err:
         log(f"Command failed due to invalid value: {val_err}", "ERROR")
         return 1
    except Exception as e:
        log(f"Command '{command}' failed with unexpected error: {e}", "ERROR")
        log(traceback.format_exc(), "DEBUG")
        return 1

    return 0 # Indicate success

if __name__ == "__main__":
    sys.exit(main())
