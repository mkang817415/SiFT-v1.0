import sys, getpass
from base64 import b64encode, b64decode
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Signature import PKCS1_PSS
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Util import Padding
from Crypto import Random
import socket
import os

class SiFT_MTP_Error(Exception):
    def __init__(self, err_msg):
        self.err_msg = err_msg

class SiFT_MTP:
    def __init__(self, peer_socket):
        self.DEBUG = True

        # --------- CONSTANTS ------------
        self.version_major = 1
        self.version_minor = 0
        self.msg_hdr_ver = b'\x01\x00'

        # Header Sizes
        self.size_msg_hdr = 16
        self.size_msg_hdr_ver = 2
        self.size_msg_hdr_typ = 2
        self.size_msg_hdr_len = 2
        self.size_msg_hdr_sqn = 2
        self.size_msg_hdr_rnd = 6
        self.size_msg_hdr_rsv = 2

        self.size_msg_etk = 256

        self.type_login_req =    b'\x00\x00'
        self.type_login_res =    b'\x00\x10'
        self.type_command_req =  b'\x01\x00'
        self.type_command_res =  b'\x01\x10'
        self.type_upload_req_0 = b'\x02\x00'
        self.type_upload_req_1 = b'\x02\x01'
        self.type_upload_res =   b'\x02\x10'
        self.type_dnload_req =   b'\x03\x00'
        self.type_dnload_res_0 = b'\x03\x10'
        self.type_dnload_res_1 = b'\x03\x11'
        self.msg_types = (self.type_login_req, self.type_login_res, 
                          self.type_command_req, self.type_command_res,
                          self.type_upload_req_0, self.type_upload_req_1, self.type_upload_res,
                          self.type_dnload_req, self.type_dnload_res_0, self.type_dnload_res_1)
        # --------- STATE ------------
        self.peer_socket = peer_socket

        # Sequence Number
        self.sequence_number = 1

        self.last_received_sqn = 0

        # Public Key 
        client_key_path = os.path.join(os.path.dirname(__file__), '../../client/keys/Applied Cryptography Public Key.pem')
        with open(client_key_path, 'rb') as f:
            public_key_string = f.read()
            self.public_key = RSA.import_key(public_key_string)

        # temporary key
        self.tk = None

        # transfer key 
        self.ftrk = None

    # sets the final transfer key
    def set_transfer_key(self, ftrk):
        self.ftrk = ftrk

    # parses a message header and returns a dictionary containing the header fields
    def parse_msg_header(self, msg_hdr):
        parsed_msg_hdr, i = {}, 0
        parsed_msg_hdr['ver'], i = msg_hdr[i:i+self.size_msg_hdr_ver], i+self.size_msg_hdr_ver 
        parsed_msg_hdr['typ'], i = msg_hdr[i:i+self.size_msg_hdr_typ], i+self.size_msg_hdr_typ
        parsed_msg_hdr['len'], i = msg_hdr[i:i+self.size_msg_hdr_len], i + self.size_msg_hdr_len

        # SQN 
        parsed_msg_hdr['sqn'], i = msg_hdr[i:i+self.size_msg_hdr_sqn], i+self.size_msg_hdr_sqn

        # RND
        parsed_msg_hdr['rnd'], i = msg_hdr[i:i+self.size_msg_hdr_rnd], i+self.size_msg_hdr_rnd

        # RSV
        parsed_msg_hdr['rsv'], i = msg_hdr[i:i+self.size_msg_hdr_rsv], i + self.size_msg_hdr_rsv

        return parsed_msg_hdr

    # receives n bytes from the peer socket
    def receive_bytes(self, n):
        bytes_received = b''
        bytes_count = 0
        while bytes_count < n:
            try:
                chunk = self.peer_socket.recv(n-bytes_count)
            except:
                raise SiFT_MTP_Error('Unable to receive via peer socket')
            if not chunk: 
                raise SiFT_MTP_Error('Connection with peer is broken')
            bytes_received += chunk
            bytes_count += len(chunk)
        return bytes_received

    # receives and parses message, returns msg_type and msg_payload
    def receive_msg(self):
        # Checking header received
        try:
            msg_hdr = self.receive_bytes(self.size_msg_hdr)
        except SiFT_MTP_Error as e:
            raise SiFT_MTP_Error('Unable to receive message header --> ' + e.err_msg)

        # Check if length of header is correct
        if len(msg_hdr) != self.size_msg_hdr: 
            raise SiFT_MTP_Error('Incomplete message header received')
        
        # Parse the header
        parsed_msg_hdr = self.parse_msg_header(msg_hdr)

        # Check version
        if parsed_msg_hdr['ver'] != self.msg_hdr_ver:
            raise SiFT_MTP_Error('Unsupported version found in message header')

        # Check message type
        if parsed_msg_hdr['typ'] not in self.msg_types:
            raise SiFT_MTP_Error('Unknown message type found in message header')

        # Check sequence number
        if int.from_bytes(parsed_msg_hdr['sqn'], byteorder='big') <= self.last_received_sqn:
            raise SiFT_MTP_Error('Sequence number not in order')

        # Type is login 
        if parsed_msg_hdr['typ'] == self.type_login_res: # or parsed_msg_hdr['typ'] == self.type_login_req:
            full_len = int.from_bytes(parsed_msg_hdr['len'], byteorder='big')
            
            # Get encrypted payload and mac
            try:
                msg_body = self.receive_bytes(full_len - self.size_msg_hdr)
                epd = msg_body[:-12]
                mac = msg_body[-12:]
            except SiFT_MTP_Error as e:
                raise SiFT_MTP_Error('Unable to receive message body --> ' + e.err_msg)

            if len(msg_body) != full_len - self.size_msg_hdr: 
                raise SiFT_MTP_Error('Incomplete message body reveived')

            nonce = parsed_msg_hdr['sqn'] + parsed_msg_hdr['rnd'] # nonce
             # AES GCM key
            AES_GCM = AES.new(self.tk, AES.MODE_GCM, nonce=nonce, mac_len=12) # AES GCM mode
            AES_GCM.update(msg_hdr) # update with encrypted payload

            # Try decrypting and verifying
            try:
                msg_payload = AES_GCM.decrypt_and_verify(epd, mac)
            except:
                raise SiFT_MTP_Error('Unable to decrypt and verify message body')

            self.last_received_sqn = int.from_bytes(parsed_msg_hdr['sqn'], byteorder='big')

            return parsed_msg_hdr['typ'], msg_payload
        else:
            
            full_len = int.from_bytes(parsed_msg_hdr['len'], byteorder='big')
            
            # Get encrypted payload and mac
            try:
                msg_body = self.receive_bytes(full_len - self.size_msg_hdr)
                epd = msg_body[:-12]
                mac = msg_body[-12:]
            except SiFT_MTP_Error as e:
                raise SiFT_MTP_Error('Unable to receive message body --> ' + e.err_msg)

            if len(msg_body) != full_len - self.size_msg_hdr: 
                raise SiFT_MTP_Error('Incomplete message body reveived')

            # Verify mac and decrypt payload with AES in GCM mode using the final transfer key as the key and sqn+rnd as the nonce
            nonce = parsed_msg_hdr['sqn'] + parsed_msg_hdr['rnd'] # nonce
            AES_GCM = AES.new(self.ftrk, AES.MODE_GCM, nonce=nonce, mac_len=12) # AES GCM mode
            AES_GCM.update(msg_hdr) 

            # Try decrypting and verifying
            try:
                msg_payload = AES_GCM.decrypt_and_verify(epd, mac)
            except Exception as e:
                raise SiFT_MTP_Error('Unable to decrypt and verify message body ' + str(e))

            self.last_received_sqn = int.from_bytes(parsed_msg_hdr['sqn'], byteorder='big')

            return parsed_msg_hdr['typ'], msg_payload

    # sends all bytes provided via the peer socket
    def send_bytes(self, bytes_to_send):
        try:
            self.peer_socket.sendall(bytes_to_send)
        except:
            raise SiFT_MTP_Error('Unable to send via peer socket')

    # builds and sends message of a given type using the provided payload
    def send_msg(self, msg_type, msg_payload):
        if msg_type == self.type_login_req: # Message is login
            # build message
            msg_size = self.size_msg_hdr + len(msg_payload) + 12 + 256 # Mac + etk
            msg_hdr_len = msg_size.to_bytes(self.size_msg_hdr_len, byteorder='big') # Big endian byte order ***

            sqn = self.sequence_number.to_bytes(2, byteorder="big") # Big endian byte order*** 
            rnd = Random.get_random_bytes(6) # freshly generated random bytes
            rsv = b'\x00\x00' # 00 for now, reserved for future versions. 

            msg_hdr = self.msg_hdr_ver + msg_type + msg_hdr_len + sqn + rnd + rsv 
            self.tk = Random.get_random_bytes(32) # 256 bits, 32 bytes AES key

            # nonce
            nonce = sqn + rnd

            #### Encryption
            AES_GCM = AES.new(key=self.tk, mode=AES.MODE_GCM, nonce=nonce, mac_len=12)
            AES_GCM.update(msg_hdr)
            epd, mac = AES_GCM.encrypt_and_digest(msg_payload) # epd = encrypted payload, mac = authentication tag

            # tk is encrypted using RSA-OAEP with the public key of the server
            RSAcipher = PKCS1_OAEP.new(self.public_key)
            etk = RSAcipher.encrypt(self.tk)
        
            try:
                whole_msg = msg_hdr + epd + mac + etk
                self.send_bytes(whole_msg)
                self.sequence_number += 1
            except SiFT_MTP_Error as e:
                raise SiFT_MTP_Error('Unable to send message to peer --> ' + e.err_msg)
        else: # Message is not login
            # build message
            msg_size = self.size_msg_hdr + len(msg_payload) + 12
            msg_hdr_len = msg_size.to_bytes(self.size_msg_hdr_len, byteorder='big')

            sqn = self.sequence_number.to_bytes(2, byteorder="big") # Big endian byte order
            rnd = Random.get_random_bytes(6) # freshly generated random bytes
            rsv = b'\x00\x00' # 00 for now, reserved for future versions. 

            msg_hdr = self.msg_hdr_ver + msg_type + msg_hdr_len + sqn + rnd + rsv 

            # nonce
            nonce = sqn + rnd

            AES_GCM = AES.new(self.ftrk, AES.MODE_GCM, nonce=nonce, mac_len=12)
            AES_GCM.update(msg_hdr)
            epd, mac = AES_GCM.encrypt_and_digest(msg_payload) 
            # try to send
 
            try:
                whole_msg = msg_hdr + epd + mac
                self.send_bytes(whole_msg)
                self.sequence_number += 1
            except SiFT_MTP_Error as e:
                raise SiFT_MTP_Error('Unable to send message to peer --> ' + e.err_msg)
