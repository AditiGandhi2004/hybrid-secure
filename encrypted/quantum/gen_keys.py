# gen_keys.py - generate RSA key pair for a user (PEM files)
from Crypto.PublicKey import RSA
import sys

def gen(name:str):
    key = RSA.generate(2048)
    priv = key.export_key()
    pub = key.publickey().export_key()
    with open(f"{name}_priv.pem","wb") as f:
        f.write(priv)
    with open(f"{name}_pub.pem","wb") as f:
        f.write(pub)
    print(f"Generated {name}_priv.pem and {name}_pub.pem")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python gen_keys.py <name>")
    else:
        gen(sys.argv[1])
