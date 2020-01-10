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
	os.write(2, "The Crypto library is required to run this script.\nNIX: 'pip (or pip3) install pycrypto'.\nWindows: 'pip install pycryptodome'.\n")

_TEMPLATE = """#! /usr/bin/python3
import os
try:
	from Crypto.Cipher import AES
	from Crypto.Protocol.KDF import PBKDF2
except ImportError:
	print("The Crypto library is required to run this script. NIX: 'pip (or pip3) install pycrypto'. Windows: 'pip install pycryptodome'. ")

import base64
import getpass
import hashlib
import argparse

parser = argparse.ArgumentParser(description="Standalone File Packager payload.")
parser.add_argument("-p", help="Password for AES encryption.", dest="pwd")
args = parser.parse_args()

data = {}
filename = {}

iv = base64.b85decode({})
salt = base64.b85decode({})
itr_len = {}

checksum = '{}'
checksum_salt = {}

password = None

if args.pwd:
	password = args.pwd
else:
	password = getpass.getpass("Input password: ")

key = PBKDF2(password, salt, AES.block_size, itr_len, None)
del password
aes = AES.new(key, AES.MODE_CBC, iv)

raw = aes.decrypt(base64.b85decode(data))
raw = raw[:-raw[-1]]

fname = aes.decrypt(base64.b85decode(filename))
fname = fname[:-fname[-1]]

if not fname:
	print("File failed to decrypt.")

try:
	fname = fname.decode()
except:
	print("File failed to decrypt.")

if hashlib.sha512(raw + checksum_salt).hexdigest() == checksum:
	print("Checksum is verified. File decrypted successfully!")
else:
	print("Checksums do NOT match! File failed to decrypt or was corrupted in transit.")
	exit()

with open(fname, "wb") as o:
    o.write(raw)
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
			os.write(2, "{} does not exist!".format(file))

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


def filename_check(s):
	# Windows forbids consecutive dots
	if ".." in s:
		return False
	# List of bad chars, taken from both linux and Windows
	for letter in "/\\<>:\"|?*":
		if letter in s:
			os.write(2, "Error:: Forbidden character '{}' in the filename override.\nIgnoring the override.\n".format(letter).encode())
			return False
	return True



if __name__ == "__main__":

	# All of the arguments!
	parser = argparse.ArgumentParser(description="Standalone File Packager with encryption.")
	group = parser.add_mutually_exclusive_group(required=True)
	group.add_argument("-f", help="Filename of target", dest="file")
	group.add_argument("-d", help="Directory of target (Will be compressed)", dest="directory")
	parser.add_argument("-V", "--version", action="version", version="%(prog)s 2.1.1")
	parser.add_argument("-p", help="Password for AES encryption", dest="pwd")
	parser.add_argument("-F", help="Filename override (default is input filename)", dest="fname_override")
	parser.add_argument("-P", help="Payload name override", dest="payload_override", default="payload.py")
	parser.add_argument("--compress", help="Compress the input file's data", dest="compress", action="store_true")
	args = parser.parse_args()

	# The compress argument is dependant on the file argument
	if args.compress and not args.file:
		parser.error("--compress argument requires the -f argument to be used.\nThe -d argument will always compress the data.")


	file = None

	# If dir, check if it exists and is valid, then zip and set file to that
	if args.directory:
		if not os.path.exists(args.directory):
			parser.error("'{}' does not exist!\n".format(args.directory))

		if not os.path.isdir(args.directory):
			parser.error("-d DIRECTORY argument was used but '{}' is not a directory.\nDid you mean -f FILE?\n".format(args.directory))

		file = os.path.basename(os.path.normpath(args.directory))
		shutil.make_archive(file, "zip", args.directory)
		file += ".zip"

	# If file, check if it exists and is valid, then set file
	if args.file:
		if not os.path.exists(args.file):
			parser.error("'{}' does not exist!\n".format(args.file))

		if not os.path.isfile(args.file):
			parser.error("-f FILE argument was used but '{}' is not a file.\nDid you mean -d DIRECTORY?\n".format(args.file))

		if args.compress:
			file = os.path.basename(os.path.normpath(args.file))
			shutil.make_archive(file, "zip", args.file)
			file += ".zip"
		else:
			file = args.file

	# Independant code block
	# If filename override, the check if its valid to override the filename 
	if args.fname_override:
		if not filename_check(args.fname_override):
			args.fname_override = None

	# Set password (default None) and delete old mem
	pwd = args.pwd
	del args.pwd

	# If password not passed via command line, then grab password
	if not pwd:
		pwd = getpass.getpass("Input password: ")
		pwd2 = getpass.getpass("Confirm password: ")

		if pwd != pwd2:
			os.write(2, "Passwords do not match.\n".encode())
			exit()

		del pwd2

	# Set up pyhide's encryption keys
	e = PyHide(pwd)
	del pwd
	# At this step there is no longer any variables with passwords (still in memory)
	# working on setting up secure deletion of strings, either with np or securestring

	script = e.create(file, args.fname_override)

	# If a zip file was made, then delete it
	if args.directory or args.compress:
		os.remove(file)


	oname = args.payload_override

	# If payload name override, then check if it contains invalid chars
	if args.payload_override:
		if not filename_check(args.payload_override):
			args.payload_override = "payload.py"

	with open(oname, "w") as o:
		o.write(script)
