#python3

import socket

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256, HMAC
from Crypto.Protocol.KDF import PBKDF2
from base64 import b64encode, b64decode
import time



class SiFT_MTP_Error(Exception):

    def __init__(self, err_msg):
        self.err_msg = err_msg

class SiFT_MTP:
	def __init__(self, peer_socket):

		self.DEBUG = True
		# --------- CONSTANTS ------------
		self.version_major = 0
		self.version_minor = 5
		self.msg_hdr_ver = b'\x00\x05'
		self.size_msg_hdr = 6
		self.size_msg_hdr_ver = 2
		self.size_msg_hdr_typ = 2
		self.size_msg_hdr_len = 2
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
  
		# Session Key
		self.session_key = None
  
		# Nonce Storage 
		self.nonce = None	
		self.received_nonce = {}
		self.nonce_timeout = 300


	# parses a message header and returns a dictionary containing the header fields
	def parse_msg_header(self, msg_hdr):

		parsed_msg_hdr, i = {}, 0
		parsed_msg_hdr['ver'], i = msg_hdr[i:i+self.size_msg_hdr_ver], i+self.size_msg_hdr_ver 
		parsed_msg_hdr['typ'], i = msg_hdr[i:i+self.size_msg_hdr_typ], i+self.size_msg_hdr_typ
		parsed_msg_hdr['len'] = msg_hdr[i:i+self.size_msg_hdr_len]
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
     
		# Receive and parse message header
		try:
			msg_hdr = self.receive_bytes(self.size_msg_hdr)
		except SiFT_MTP_Error as e:
			raise SiFT_MTP_Error('Unable to receive message header --> ' + e.err_msg)

		if len(msg_hdr) != self.size_msg_hdr: 
			raise SiFT_MTP_Error('Incomplete message header received')
		
		parsed_msg_hdr = self.parse_msg_header(msg_hdr)

		if parsed_msg_hdr['ver'] != self.msg_hdr_ver:
			raise SiFT_MTP_Error('Unsupported version found in message header')

		if parsed_msg_hdr['typ'] not in self.msg_types:
			raise SiFT_MTP_Error('Unknown message type found in message header')

		msg_len = int.from_bytes(parsed_msg_hdr['len'], byteorder='big')

		try:
			encrypted_body = self.receive_bytes(msg_len - self.size_msg_hdr)
		except SiFT_MTP_Error as e:
			raise SiFT_MTP_Error('Unable to receive message body --> ' + e.err_msg)

		# DEBUG 
		if self.DEBUG:
			print('MTP message received (' + str(msg_len) + '):')
			print('HDR (' + str(len(msg_hdr)) + '): ' + msg_hdr.hex())
			print('BDY (' + str(len(encrypted_body)) + '): ')
			print(encrypted_body.hex())
			print('------------------------------------------')
   
		# DEBUG 
		if len(encrypted_body) != msg_len - self.size_msg_hdr: 
			raise SiFT_MTP_Error('Incomplete message body reveived')

		# Decrypt the message payload using AES with session key
		if not hasattr(self, 'session_key'):
			raise SiFT_MTP_Error('Session key not found')


		nonce = encrypted_body[:16] 
		tag = encrypted_body[16:32]
		ciphertext = encrypted_body[32:]

		# Relay protecting: check if nonce was already received 
		current_time = time.time()
		if nonce in self.received_nonce:
			if current_time - self.received_nonce[nonce] < self.nonce_timeout:
				raise SiFT_MTP_Error('Relay detected. Nonce already received')
		self.received_nonce[nonce] = current_time
  
		# Remove expired nonce from the record
		self.receive_nonces = {k:v for k,v in self.received_nonce.items() if current_time - v < self.nonce_timeout}
  
		print("Session Key: ", self.session_key)


		aes = AES.new(self.session_key, AES.MODE_GCM, nonce=nonce)
		try:
			msg_body = aes.decrypt_and_verify(ciphertext, tag)
		except Exception as e:
			raise SiFT_MTP_Error('Decryption or verification of message body failed' + str(e))
      
		received_nonce = msg_body[:16]
		actual_msg_body = msg_body[16:]
  
		return parsed_msg_hdr['typ'], actual_msg_body


	# sends all bytes provided via the peer socket
	def send_bytes(self, bytes_to_send):
		try:
			self.peer_socket.sendall(bytes_to_send)
		except:
			raise SiFT_MTP_Error('Unable to send via peer socket')


	# builds and sends message of a given type using the provided payload
	def send_msg(self, msg_type, msg_payload):
		if not hasattr(self, 'session_key'):
			raise SiFT_MTP_Error('Session key not found')



		# Generate Random Nonce 
		nonce = get_random_bytes(16)
		timestamped_nonce = nonce + int(time.time()).to_bytes(4, byteorder='big')
  
		msg_payload_with_nonce = timestamped_nonce + msg_payload

		# Encrypt payload using AES with session key
		aes = AES.new(self.session_key, AES.MODE_GCM)
		ciphertext, tag = aes.encrypt_and_digest(msg_payload_with_nonce)
  
		# Combine nonce, tag, and ciphertext for sending via MTP
		encrypted_payload = aes.nonce + tag + ciphertext
		
		# build message
		msg_size = self.size_msg_hdr + len(encrypted_payload)
		msg_hdr_len = msg_size.to_bytes(self.size_msg_hdr_len, byteorder='big')
		msg_hdr = self.msg_hdr_ver + msg_type + msg_hdr_len

		# DEBUG 
		if self.DEBUG:
			print('MTP message to send (' + str(msg_size) + '):')
			print('HDR (' + str(len(msg_hdr)) + '): ' + msg_hdr.hex())
			print('BDY (' + str(len(encrypted_payload)) + '): ')
			print(encrypted_payload.hex())
			print('------------------------------------------')
		# DEBUG 
		
		# try to send
		try:
			self.send_bytes(msg_hdr + encrypted_payload)
		except SiFT_MTP_Error as e:
			raise SiFT_MTP_Error('Unable to send message to peer --> ' + e.err_msg)


