# kyber_fallback.py - insecure simulated KEM for demo only (NOT SECURE)
import os
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256

def generate_keypair():
    priv = os.urandom(32)
    pub = os.urandom(32)
    return pub, priv

def encapsulate(pub):
    secret = os.urandom(32)
    ct = os.urandom(64)
    shared = HKDF(secret, 32, b'', SHA256)
    return ct, shared

def decapsulate(ct, priv):
    shared = HKDF(priv + ct, 32, b'', SHA256)
    return shared
