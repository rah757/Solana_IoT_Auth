# Securing IoT Device Communication with Solana DevNet

This project implements a decentralized, trustless framework for secure IoT messaging using Solana DevNet Memo transactions.

## Repository Structure

```
/
├── master
│   ├── admin_registry.py       # register/revoke device keys via Solana Memo
│   └── admin_wallet.json       # admin keypair for DevNet operations
├── piCode
│   ├── generateDevnetWallet.py # create & fund a DevNet wallet for a Pi
│   └── piMain.py               # device logic: discover, challenge, key exchange, send/poll
└── README.md                   # this document
```

## Prerequisites

* Python 3.9 or later
* `solana`, `pynacl`, `requests` Python packages
* Solana DevNet access (no mainnet usage)

## Installation

```bash
git clone https://github.com/yourusername/solana_iot_auth.git
cd solana_iot_auth
python3 -m venv venv
source venv/bin/activate
pip install solana pynacl requests
```

## Admin Commands

* **Register** a device:

  ```bash
  cd master
  python admin_registry.py register <DEVICE_PUBKEY>
  ```
* **Revoke** a device:

  ```bash
  python admin_registry.py revoke <DEVICE_PUBKEY>
  ```

## Device Commands

* **Generate & fund** a DevNet wallet:

  ```bash
  cd piCode
  python generateDevnetWallet.py
  solana airdrop 1 YOUR_WALLET_ADDRESS -u devnet
  ```
* **Discover** registered peers:

  ```bash
  python piMain.py discover
  ```
* **Challenge–response & key exchange**:

  ```bash
  python piMain.py challenge
  python piMain.py receivekey
  ```
* **Send** an encrypted message:

  ```bash
  python piMain.py send "Your message here"
  ```
* **Poll** for incoming messages:

  ```bash
  python piMain.py poll
  ```

---

Fully implemented and tested on Solana DevNet.
