from solders.keypair   import Keypair
from solders.pubkey    import Pubkey
import base58, json

# 1) create a new ed25519 keypair
kp = Keypair()

# 2) save the raw bytes in base58
raw  = bytes(kp)                   # 64 bytes: seed||pubkey
b58  = base58.b58encode(raw).decode()
pub  = str(kp.pubkey())            # Solana‐style pubkey

with open("wallet.json","w") as f:
    json.dump({"keypair": b58, "pubkey": pub}, f)

print("🎉 new wallet →", pub)