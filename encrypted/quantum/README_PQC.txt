# quantum - PQC helper add-on (hybrid)
This archive was augmented to include a **hybrid encryption module** that works out-of-the-box on **Windows 11** with **Python 3.10** and PowerShell.

Important notes
- The provided `pqc_hybrid.py` implements **X25519 (ECDH)** + **AES-GCM** hybrid encryption. **This is *not* a post-quantum algorithm.** It is a practical, well-supported hybrid that runs without building native PQC libraries.
- True PQC KEMs (Kyber, NTRU, etc.) require native libraries (liboqs or vendor implementations) and Python bindings that must be built on your machine; those are **not** included here because they typically need compilation on Windows.

Files added
- `quantum/pqc_hybrid.py` — hybrid encrypt/decrypt module and simple CLI
- `quantum/README_PQC.txt` — this file (explanation + next steps)
- `requirements-pqc.txt` — recommended pip packages to install

How to use (PowerShell)
1. Create a new virtualenv (recommended) and activate it in PowerShell:
   python -m venv .venv
   .\\.venv\\Scripts\\Activate.ps1

2. Install requirements:
   pip install -r requirements-pqc.txt

3. Quick Python usage example:
   ```py
   from pqc_hybrid import generate_keypair, encode_public_key, encode_private_key, encrypt, decrypt, decode_private_key
   sk, pk = generate_keypair()
   pk_bytes = encode_public_key(pk)
   ct, meta = encrypt(pk_bytes, b"hello pqc? not exactly")
   pt = decrypt(sk, ct, meta)
   print(pt)
   ```

If you need *real* PQC (Kyber, NTRU, etc.)
- I recommend using the Open Quantum Safe project (liboqs) and the Python bindings (`python-oqs` / `oqs` package). On Windows you'll typically install a prebuilt wheel or build liboqs yourself — instructions are here: https://github.com/open-quantum-safe/liboqs and https://github.com/open-quantum-safe/pyoqs
- If `ntru` specifically won't work on your system, consider trying `Kyber` via liboqs/pyoqs — but it still requires native libs.
- If you'd like, I can add scripts that attempt to download and install a Windows wheel for `oqs` automatically, but building may still be required.

If you'd like me to try packaging liboqs+pyoqs in this archive for Windows, tell me and I will attempt it (it may fail on some systems and will increase archive size).
