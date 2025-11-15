# quantum — Hybrid E2E Encryption 

Quick start (PowerShell):

1. `cd` into the folder.
2. Create a venv and activate it (PowerShell):
   powershell
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1
   python -m pip install --upgrade pip
   
3. Install dependencies:
   powershell
   pip install -r requirements.txt
  
4. Generate keys:
   powershell
   python gen_keys.py alice
   python gen_keys.py bob
   
5. Start server (window 1):
   powershell
   python server.py
   
6. Start clients (window 2 and 3):
   powershell
   python client.py --name alice --peer bob --pub alice_pub.pem --priv alice_priv.pem
   python client.py --name bob --peer alice --pub bob_pub.pem --priv bob_priv.pem
   
7. Type messages and press Enter. Messages are encrypted end-to-end; server only relays ciphertext.

 install liboqs-python or pypqc and re-run inside the venv.
