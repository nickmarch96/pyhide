import sys
import base64
import getpass
import os
import random
import argparse
import shutil
import hashlib

try:
	from Crypto.Cipher import AES
	from Crypto.Protocol.KDF import PBKDF2
except ImportError:
	raise Exception("The Crypto library is required to run this script. NIX: 'pip (or pip3) install pycrypto'. Windows: 'pip install pycryptodome'.")

_TEMPLATE = """#! /usr/bin/python3
try:
	from Crypto.Cipher import AES
	from Crypto.Protocol.KDF import PBKDF2
except ImportError:
	raise Exception("The Crypto library is required to run this script. NIX: 'pip install pycrypto'. Windows: 'pip install pycryptodome'.")

import base64
import getpass
import hashlib

data = {}
filename = {}

iv = base64.b85decode({})
salt = base64.b85decode({})
itr_len = {}

checksum = '{}'
checksum_salt = {}

password = getpass.getpass("Input password: ")
key = PBKDF2(password, salt, AES.block_size, itr_len, None)
del password
aes = AES.new(key, AES.MODE_CBC, iv)

raw = aes.decrypt(base64.b85decode(data))
raw = raw[:-raw[-1]]

fname = aes.decrypt(base64.b85decode(filename))
fname = fname[:-fname[-1]]

if not fname:
	raise Exception("File failed to decrypt.")

try:
	fname = fname.decode()
except:
	raise Exception("File failed to decrypt.")

with open(fname, "wb") as o:
    o.write(raw)

if hashlib.sha512(open(fname, "rb").read() + checksum_salt).hexdigest() == checksum:
	print("Checksum is verified. File decrypted successfully!")
else:
	raise Exception("Checksums do NOT match! File failed to decrypt or was corrupted in transit.")
"""



class PyHide():
	"""
	The encrypting and encoding class
	"""

	def __init__(self, password):
		self.__IV = os.urandom(AES.block_size)
		self.__SALT = os.urandom(AES.block_size)
		self.__C_SALT = os.urandom(AES.block_size)
		self.__ITR_LEN = random.randint(1000, 10000)
		self.__KEY = PBKDF2(password, self.__SALT, AES.block_size, self.__ITR_LEN, None)
		del password

		self.aes = AES.new(self.__KEY, AES.MODE_CBC, self.__IV)

		self.filename = None
		self.data = None

	def create(self, file, filename_override=None):
		if os.path.exists(file):
			pass
		else:
			raise Exception("{} does not exist!".format(file))

		with open(file, "rb") as f:
			data = f.read()

		checksum = hashlib.sha512(data + self.__C_SALT).hexdigest()

		data = self._pad(data)
		data = base64.b85encode(self.aes.encrypt(data))

		if filename_override:
			file = filename_override

		file = os.path.basename(os.path.normpath(file))
		file = self._pad(file.encode())
		file = base64.b85encode(self.aes.encrypt(file))

		script = _TEMPLATE.format(data, file, base64.b85encode(self.__IV), 
							base64.b85encode(self.__SALT), self.__ITR_LEN, checksum, self.__C_SALT)

		return script

	def _pad(self, raw):
		t = AES.block_size - len(raw) % AES.block_size
		return raw + (chr(t)*t).encode()


if __name__ == "__main__":

	parser = argparse.ArgumentParser(description="Standalone File Packager with encryption.")
	group = parser.add_mutually_exclusive_group(required=True)
	group.add_argument("-f", help="Filename of target.", dest="file")
	group.add_argument("-d", help="Directory of target. (Will be compressed)", dest="directory")
	parser.add_argument("-V", "--version", action="version", version="%(prog)s 2.1")
	parser.add_argument("-p", help="Password for AES encryption.", dest="pwd")
	parser.add_argument("-o", help="Filename override (default is input filename)", dest="fname_override")
	args = parser.parse_args()

	file = None

	if args.directory:
		if not os.path.exists(args.directory):
			raise Exception("'{}' does not exist!".format(args.directory))

		if not os.path.isdir(args.directory):
			raise Exception("-d DIRECTORY argument was used but '{}' is not a directory.".format(args.directory))

		file = os.path.basename(os.path.normpath(args.directory))
		shutil.make_archive(file, "zip", args.directory)
		file += ".zip"

	if args.file:
		if not os.path.exists(args.file):
			raise Exception("'{}' does not exist!".format(args.file))

		if not os.path.isfile(args.file):
			raise Exception("-f FILE argument was used but '{}' is not a file.".format(args.file))

		file = args.file

	if args.fname_override:
		for letter in "/\\<>:\"|?*":
			if letter in args.fname_override:
				os.write(2, "Error:: Forbidden character '{}' in the filename override.\nIgnoring the override.\n".format(letter).encode())
				args.fname_override = None
				break

	pwd = args.pwd
	del args.pwd

	if not pwd:
		pwd = getpass.getpass("Input password: ")
		pwd2 = getpass.getpass("Confirm password: ")

		if pwd != pwd2:
			raise Exception("Passwords do not match.")

		del pwd2

	e = PyHide(pwd)
	del pwd

	script = e.create(file, args.fname_override)

	if args.directory:
		os.remove(file)



	with open("payload.py", "w") as o:
		o.write(script)
