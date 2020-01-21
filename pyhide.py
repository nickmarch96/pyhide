import sys
import base64
import getpass
import os
import random
import argparse
import shutil
import hashlib
from time import time

try:
	from Crypto.Cipher import AES
	from Crypto.Protocol.KDF import PBKDF2
except ImportError:
	os.write(2, "The Crypto library is required to run this script.\nNIX: 'pip (or pip3) install pycrypto'.\nWindows: 'pip install pycryptodome'.\n".encode())

_TEMPLATE = """#! /usr/bin/python3
import os
try:
	from Crypto.Cipher import AES
	from Crypto.Protocol.KDF import PBKDF2
except ImportError:
	os.write(2, "The Crypto library is required to run this script. NIX: 'pip (or pip3) install pycrypto'. Windows: 'pip install pycryptodome'.\\n".encode())

import base64
import getpass
import hashlib
import argparse
from time import time

parser = argparse.ArgumentParser(description="Standalone File Packager payload.")
parser.add_argument("-p", help="Password for AES encryption.", dest="pwd")
args = parser.parse_args()

data = {}
filename = {}

iv = [base64.b85decode({}), base64.b85decode({})]

salt = [base64.b85decode({}), base64.b85decode({})]

iter_len = [{}, {}]

checksum = '{}'
checksum_salt = {}

password = None

if args.pwd:
	password = args.pwd
else:
	password = getpass.getpass("Input password: ")

os.write(1, "Decrypting...".encode())
t1 = time()
aes_data = AES.new(PBKDF2(password, salt[0], AES.block_size, iter_len[0], None), AES.MODE_CBC, iv[0])
aes_fname = AES.new(PBKDF2(password, salt[1], AES.block_size, iter_len[1], None), AES.MODE_CBC, iv[1])
t2 = time()
del password
os.write(1, "Done. Took {} seconds.\\n".format(round(t2-t1, 3)).encode())


raw = aes_data.decrypt(base64.b85decode(data))
raw = raw[:-raw[-1]]

fname = aes_fname.decrypt(base64.b85decode(filename))
fname = fname[:-fname[-1]]

if not fname:
	os.write(1, "File failed to decrypt.\\n".encode())

try:
	fname = fname.decode()
except:
	os.write(1, "File failed to decrypt.\\n".encode())

if hashlib.sha512(raw + checksum_salt).hexdigest() == checksum:
	os.write(1, "Checksum is verified. File decrypted successfully!\\n".encode())
else:
	os.write(1, "Checksums do NOT match! File failed to decrypt or was corrupted in transit.\\n".encode())
	exit()

with open(fname, "wb") as o:
    o.write(raw)
"""



class PyHide():
	"""
	The encrypting and encoding class
	"""

	def __init__(self, password):
		self.__DATA_IV = os.urandom(AES.block_size)
		self.__FNAME_IV = os.urandom(AES.block_size)

		self.__DATA_SALT = os.urandom(AES.block_size)
		self.__FNAME_SALT = os.urandom(AES.block_size)
		self.__CSUM_SALT = os.urandom(AES.block_size)

		self.__DATA_ITR_LEN = random.randint(100000, 200000)
		self.__FNAME_ITR_LEN = random.randint(100000, 200000)

		os.write(1, "Performing Key Derivation for {} total iterations...".format(self.__DATA_ITR_LEN + self.__FNAME_ITR_LEN).encode())
		t1 = time()
		self.__DATA_KEY = PBKDF2(password, self.__DATA_SALT, AES.block_size, self.__DATA_ITR_LEN, None)
		self.__FNAME_KEY = PBKDF2(password, self.__FNAME_SALT, AES.block_size, self.__FNAME_ITR_LEN, None)
		t2 = time()
		del password
		os.write(1, "Done. Took {} seconds.\n".format(round(t2-t1, 3)).encode())

		self.aes_data = AES.new(self.__DATA_KEY, AES.MODE_CBC, self.__DATA_IV)
		self.aes_fname = AES.new(self.__FNAME_KEY, AES.MODE_CBC, self.__FNAME_IV)

		self.filename = None
		self.data = None

	def create(self, file, filename_override=None):
		if os.path.exists(file):
			pass
		else:
			os.write(2, "{} does not exist!".format(file))

		with open(file, "rb") as f:
			data = f.read()

		checksum = hashlib.sha512(data + self.__CSUM_SALT).hexdigest()

		data = self._pad(data)
		data = base64.b85encode(self.aes_data.encrypt(data))

		if filename_override:
			file = filename_override

		file = os.path.basename(os.path.normpath(file))
		file = self._pad(file.encode())
		file = base64.b85encode(self.aes_fname.encrypt(file))

		script = _TEMPLATE.format(data, file,
							base64.b85encode(self.__DATA_IV), base64.b85encode(self.__FNAME_IV), 
							base64.b85encode(self.__DATA_SALT), base64.b85encode(self.__FNAME_SALT),
							self.__DATA_ITR_LEN, self.__FNAME_ITR_LEN, checksum, self.__CSUM_SALT, "{}")

		return script

	def _pad(self, raw):
		t = AES.block_size - len(raw) % AES.block_size
		return raw + (chr(t)*t).encode()


if __name__ == "__main__":

	parser = argparse.ArgumentParser(description="Standalone File Packager with encryption.")
	group = parser.add_mutually_exclusive_group(required=True)
	group.add_argument("-f", help="Filename of target", dest="file")
	group.add_argument("-d", help="Directory of target (Will be compressed)", dest="directory")
	parser.add_argument("-p", help="Password for AES encryption.", dest="pwd")
	parser.add_argument("-F", help="Filename override (default is input filename)", dest="fname_override")
	parser.add_argument("-P", help="Payload name override", dest="payload_override")
	parser.add_argument("-V", "--version", action="version", version="%(prog)s 2.1")
	args = parser.parse_args()

	file = None

	if args.directory:
		if not os.path.exists(args.directory):
			os.write(2, "'{}' does not exist!\n".format(args.directory).encode())
			exit()

		if not os.path.isdir(args.directory):
			os.write(2, "-d DIRECTORY argument was used but '{}' is not a directory.\nDid you mean -f FILE?\n".format(args.directory).encode())
			exit()

		file = os.path.basename(os.path.normpath(args.directory))
		shutil.make_archive(file, "zip", args.directory)
		file += ".zip"

	if args.file:
		if not os.path.exists(args.file):
			os.write(2, "'{}' does not exist!\n".format(args.file).encode())
			exit()

		if not os.path.isfile(args.file):
			os.write(2, "-f FILE argument was used but '{}' is not a file.\nDid you mean -d DIRECTORY?\n".format(args.file).encode())
			exit()

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
			os.write(2, "Passwords do not match.\n".encode())

		del pwd2

	e = PyHide(pwd)
	del pwd

	script = e.create(file, args.fname_override)

	if args.directory:
		os.remove(file)

	oname = "payload.py"

	if args.payload_override:
		oname = args.payload_override
		for letter in "/\\<>:\"|?*":
			if letter in args.fname_override:
				os.write(2, "Error:: Forbidden character '{}' in the payload name override.\nIgnoring the override.\n".format(letter).encode())
				oname = "payload.py"
				break

	with open(oname, "w") as o:
		o.write(script)
