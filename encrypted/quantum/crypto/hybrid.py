# hybrid.py - hybrid cryptography utilities (tries real PQ libs, else fallback)
import json
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

# Try to import real PQ libs (optional)
_kem = None
try:
    import oqs
    _kem = 'liboqs'
except Exception:
    try:
        import pypqc
        _kem = 'pypqc'
    except Exception:
        _kem = None

# fallback implementation
from crypto.kyber_fallback import generate_keypair, encapsulate, decapsulate

def rsa_sign(priv_pem: bytes, message: bytes) -> bytes:
    key = RSA.import_key(priv_pem)
    h = SHA256.new(message)
    signature = pkcs1_15.new(key).sign(h)
    return signature

def rsa_verify(pub_pem: bytes, message: bytes, signature: bytes) -> bool:
    key = RSA.import_key(pub_pem)
    h = SHA256.new(message)
    try:
        pkcs1_15.new(key).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False

def aes_encrypt(key: bytes, plaintext: bytes) -> dict:
    iv = get_random_bytes(12)
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    ct, tag = cipher.encrypt_and_digest(plaintext)
    return {'iv': iv.hex(), 'ct': ct.hex(), 'tag': tag.hex()}

def aes_decrypt(key: bytes, data: dict) -> bytes:
    iv = bytes.fromhex(data['iv'])
    ct = bytes.fromhex(data['ct'])
    tag = bytes.fromhex(data['tag'])
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    pt = cipher.decrypt_and_verify(ct, tag)
    return pt

# KEM wrappers
def kem_generate_keypair():
    if _kem == 'liboqs':
        kem = oqs.KeyEncapsulation('Kyber512')
        pk, sk = kem.generate_keypair()
        return pk, sk
    elif _kem == 'pypqc':
        try:
            from pypqc.kem import kyber512
            sk, pk = kyber512.keypair()
            return pk, sk
        except Exception:
            pass
    return generate_keypair()

def kem_encapsulate(pub):
    if _kem == 'liboqs':
        kem = oqs.KeyEncapsulation('Kyber512')
        ct, ss = kem.encap_secret(pub)
        return ct, ss
    elif _kem == 'pypqc':
        try:
            from pypqc.kem import kyber512
            ct, ss = kyber512.encaps(pk=pub)
            return ct, ss
        except Exception:
            pass
    return encapsulate(pub)

def kem_decapsulate(ct, priv):
    if _kem == 'liboqs':
        kem = oqs.KeyEncapsulation('Kyber512')
        ss = kem.decap_secret(ct, priv)
        return ss
    elif _kem == 'pypqc':
        try:
            from pypqc.kem import kyber512
            ss = kyber512.decaps(ciphertext=ct, sk=priv)
            return ss
        except Exception:
            pass
    return decapsulate(ct, priv)

# High level hybrid encrypt/decrypt
def hybrid_encrypt(recipient_kem_pub, sender_rsa_priv_pem: bytes, plaintext: bytes):
    ct_kem, shared = kem_encapsulate(recipient_kem_pub)
    if isinstance(shared, str):
        shared = shared.encode()
    key = SHA256.new(shared).digest()[:32]
    enc = aes_encrypt(key, plaintext)
    payload = json.dumps({'kem_ct': ct_kem.hex() if isinstance(ct_kem, (bytes,bytearray)) else str(ct_kem), 'enc': enc}).encode()
    signature = rsa_sign(sender_rsa_priv_pem, payload)
    package = {'payload': payload.hex(), 'signature': signature.hex()}
    return package

def hybrid_decrypt(recipient_kem_priv, sender_rsa_pub_pem: bytes, package: dict):
    payload = bytes.fromhex(package['payload'])
    signature = bytes.fromhex(package['signature'])
    if not rsa_verify(sender_rsa_pub_pem, payload, signature):
        raise ValueError('RSA signature verification failed')
    data = json.loads(payload.decode())
    kem_ct = bytes.fromhex(data['kem_ct'])
    enc = data['enc']
    shared = kem_decapsulate(kem_ct, recipient_kem_priv)
    if isinstance(shared, str):
        shared = shared.encode()
    key = SHA256.new(shared).digest()[:32]
    plaintext = aes_decrypt(key, enc)
    return plaintext
