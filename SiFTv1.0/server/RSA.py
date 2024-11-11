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
    with open(server_keys_dir + '/server_rsa_keypair.pem', 'wb') as f:
        keypairExport = keypair.export_key(format="PEM", passphrase = 'your_key')
        f.write(keypairExport)
    
    # Export public key without passphrase
    with open(client_keys_dir + '/server_rsa_public_key.pem', 'wb') as f:
        pubkey = keypair.publickey().export_key(format='PEM')
        f.write(pubkey)
    
    return keypair.publickey(), keypair

# RSA Encryption
def RSAEncryption(pubkey, plaintext):
    cipher = PKCS1_OAEP.new(pubkey)
    ciphertext = cipher.encrypt(plaintext)
    return b64encode(ciphertext).decode('ASCII')

def RSADecryption(privkey, ciphertext):
    cipher = PKCS1_OAEP.new(privkey)
    try:
        decrypted_message = cipher.decrypt(b64decode(ciphertext))
        return decrypted_message.decode('ASCII')
    except ValueError:
        print('Invalid ciphertext or key')
        return None
    
# RSA Signature Generation
def RSASignatureGeneration(privkey, msg):
    hashFunction = SHA256.new()
    hashFunction.update(msg)
    signer = PKCS1_PSS.new(privkey)
    signature = signer.sign(hashFunction)
    return signature.hex()

# RSA Signature verification
def RSASignatureVerification(pubkey, msg, signature):
    hashFunction = SHA256.new()
    hashFunction.update(msg)
    verifier = PKCS1_PSS.new(pubkey)
    try:
        verifier.verify(hashFunction, bytes.fromhex(signature))
        return True
    except:
        return False
    
if __name__ == '__main__':
    pubkey, keypair = keypairGeneratation()
    print("Public Key:", pubkey)
    print("Private Key:", keypair)
    
    # Example message 
    message = b'Hello this is a test'
    
    # Encryption 
    ciphertext = RSAEncryption(pubkey, message)
    print("Ciphertext (Base64):", ciphertext)   
    
    # Decryption
    plaintext = RSADecryption(keypair, ciphertext)
    if plaintext: 
        print("Recovered Plaintext:", plaintext)

    # Signature Generation
    signature = RSASignatureGeneration(keypair, message)
    print("Signature (Hex):", signature)

    # Signature Verification
    if RSASignatureVerification(pubkey, message, signature):
        print("Signature is valid")
    else:
        print("Signature is invalid")

