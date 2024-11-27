from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from base64 import b64encode, b64decode
from Crypto.Signature import PKCS1_PSS
from Crypto.Hash import SHA256

import os


# RSA Key Generation
def keypairGeneratation():
    
    # Server & Client Key Directory
    server_keys_dir = os.path.join(os.path.dirname(__file__), 'keys')        
    client_keys_dir = server_keys_dir.replace('server', 'client')
    
    # Generate keypair
    keypair = RSA.generate(2048)
    
    # Export Private Key with a passphrase 
    with open(server_keys_dir + '/keypair.pem', 'wb') as f:
        keypairExport = keypair.export_key(format="PEM", passphrase = 'your_key')
        f.write(keypairExport)
    
    # Export public key without passphrase
    with open(client_keys_dir + '/public_key.pem', 'wb') as f:
        pubkey = keypair.publickey().export_key(format='PEM')
        f.write(pubkey)
    
    return keypair.publickey(), keypair

    
if __name__ == '__main__':
    pubkey, keypair = keypairGeneratation()
    print("Public Key:", pubkey)
    print("Private Key:", keypair)
    