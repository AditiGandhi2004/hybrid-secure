"""
pqc_hybrid.py

Hybrid encryption using X25519 (Elliptic-curve Diffie-Hellman) + AES-GCM symmetric encryption.
This is NOT post-quantum cryptography (PQC). It's a practical, cross-platform hybrid
scheme that works on Windows with Python 3.10 and the 'cryptography' package only,
so it will run in PowerShell without WSL.

If you need true PQC KEMs (Kyber, NTRU, etc.), you'll need a library such as liboqs and
python bindings (oqs), which require building native libraries on Windows. See README.md.

Usage (example):
    from pqc_hybrid import generate_keypair, encrypt, decrypt, encode_public_key, decode_public_key
    # generate recipient keypair and save public key
    sk, pk = generate_keypair()
    pk_bytes = encode_public_key(pk)
    # sender encrypts
    ciphertext, enc_meta = encrypt(pk_bytes, b"hello world")
    # recipient decrypts
    pt = decrypt(sk, ciphertext, enc_meta)
"""

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os, json, base64, typing

def generate_keypair():
    """Return (private_key, public_key) as objects."""
    sk = x25519.X25519PrivateKey.generate()
    pk = sk.public_key()
    return sk, pk

def encode_public_key(pubkey: x25519.X25519PublicKey) -> bytes:
    """Return raw 32-byte public key bytes."""
    return pubkey.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)

def decode_public_key(pk_bytes: bytes) -> x25519.X25519PublicKey:
    return x25519.X25519PublicKey.from_public_bytes(pk_bytes)

def encode_private_key(privkey: x25519.X25519PrivateKey) -> bytes:
    return privkey.private_bytes(encoding=serialization.Encoding.Raw, format=serialization.PrivateFormat.Raw, encryption_algorithm=serialization.NoEncryption())

def decode_private_key(sk_bytes: bytes) -> x25519.X25519PrivateKey:
    return x25519.X25519PrivateKey.from_private_bytes(sk_bytes)

def _derive_shared_key(sending_priv: x25519.X25519PrivateKey, recipient_pub: x25519.X25519PublicKey, info: bytes=b"pqc-hybrid") -> bytes:
    shared = sending_priv.exchange(recipient_pub)
    # HKDF-SHA256 derive 32 bytes
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info)
    return hkdf.derive(shared)

def encrypt(recipient_pub_bytes: bytes, plaintext: bytes) -> typing.Tuple[bytes, dict]:
    """
    Encrypt plaintext to recipient public key bytes.
    Returns (ciphertext, metadata) where metadata contains:
      - eph_public: base64 ephemeral public key bytes (sender's ephemeral X25519 pubkey)
      - nonce: base64 nonce for AESGCM
    """
    recipient_pub = decode_public_key(recipient_pub_bytes)
    # ephemeral keypair
    eph_sk = x25519.X25519PrivateKey.generate()
    eph_pk = eph_sk.public_key()
    shared_key = _derive_shared_key(eph_sk, recipient_pub, info=b"pqc-hybrid-v1")
    # AES-GCM with 12-byte nonce
    aesgcm = AESGCM(shared_key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, plaintext, associated_data=None)
    meta = {
        "eph_public": base64.b64encode(encode_public_key(eph_pk)).decode('ascii'),
        "nonce": base64.b64encode(nonce).decode('ascii'),
        "kdf": "HKDF-SHA256",
        "scheme": "X25519+AESGCM-hybrid-v1"
    }
    return ct, meta

def decrypt(recipient_priv: x25519.X25519PrivateKey, ciphertext: bytes, meta: dict) -> bytes:
    eph_pub_b = base64.b64decode(meta["eph_public"])
    nonce = base64.b64decode(meta["nonce"])
    eph_pub = decode_public_key(eph_pub_b)
    shared_key = _derive_shared_key(recipient_priv, eph_pub, info=b"pqc-hybrid-v1")
    aesgcm = AESGCM(shared_key)
    pt = aesgcm.decrypt(nonce, ciphertext, associated_data=None)
    return pt

# Simple CLI for quick tests when run directly
if __name__ == "__main__":
    import argparse, sys
    p = argparse.ArgumentParser(description="Simple hybrid encrypt/decrypt demo (X25519 + AES-GCM)")
    p.add_argument("--gen", action="store_true", help="generate keypair and print base64 keys")
    p.add_argument("--enc", nargs=2, metavar=("PUB_B64","FILE"), help="encrypt FILE to base64 public key")
    p.add_argument("--dec", nargs=2, metavar=("PRIV_HEX","FILE"), help="decrypt FILE with raw private key hex")
    args = p.parse_args()
    if args.gen:
        sk, pk = generate_keypair()
        sk_b = encode_private_key(sk).hex()
        pk_b = encode_public_key(pk).hex()
        print("PRIVATE_HEX:", sk_b)
        print("PUBLIC_HEX :", pk_b)
        sys.exit(0)
    if args.enc:
        pub_hex = args.enc[0]
        fn = args.enc[1]
        pub = bytes.fromhex(pub_hex)
        with open(fn,"rb") as f:
            pt = f.read()
        ct, meta = encrypt(pub, pt)
        out = {"ciphertext": base64.b64encode(ct).decode('ascii'), "meta": meta}
        print(json.dumps(out))
        sys.exit(0)
    if args.dec:
        priv_hex = args.dec[0]
        fn = args.dec[1]
        priv = bytes.fromhex(priv_hex)
        with open(fn,"rb") as f:
            j = f.read()
        obj = json.loads(j)
        ct = base64.b64decode(obj["ciphertext"])
        pt = decrypt(decode_private_key(priv), ct, obj["meta"])
        sys.stdout.buffer.write(pt)
