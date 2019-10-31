import base64
import getpass
import sys
import os
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Protocol.KDF import PBKDF2
import random


_TEMPLATE = """#! /usr/bin/python3
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
import base64
import getpass

password = getpass.getpass("Input password: ")

data = {}
filename = "{}"

iv = base64.b64decode({})
salt = base64.b64decode({})
itr_len = {}

key = PBKDF2(password, salt, AES.block_size, itr_len, None)
aes = AES.new(key, AES.MODE_CBC, iv)

raw = aes.decrypt(base64.b64decode(data))
raw = raw[:-raw[-1]]

with open(filename, "wb") as o:
    o.write(raw)
"""



class PyHide():
	"""
	The encrypting and encoding class
	"""

	def __init__(self, password):
		self.__IV = Random.new().read(AES.block_size)
		self.__SALT = Random.new().read(AES.block_size)
		self.__ITR_LEN = random.randint(1000, 10000)
		self.__KEY = PBKDF2(password, self.__SALT, AES.block_size, self.__ITR_LEN, None)

		self.aes = AES.new(self.__KEY, AES.MODE_CBC, self.__IV)

		self.filename = None
		self.data = None



	def create(self, file):
		if os.path.exists(file):
			pass
		else:
			raise Exception("{} does not exist!".format(file))

		with open(file, "rb") as f:
			data = f.read()
		data = self._pad(data)
		data = base64.b64encode(self.aes.encrypt(data))

		script = _TEMPLATE.format(data, file.split("/")[-1], base64.b64encode(self.__IV), 
							base64.b64encode(self.__SALT), self.__ITR_LEN)

		return script

	def _pad(self, raw):
		t = AES.block_size - len(raw) % AES.block_size
		return raw + (chr(t)*t).encode()


if __name__ == "__main__":

	if len(sys.argv) != 2:
		print("usage: ./pyhide.py <filename>")
		exit()

	filename = sys.argv[1]

	pwd1 = getpass.getpass("Input password: ")
	pwd2 = getpass.getpass("Confirm password: ")

	if pwd1 != pwd2:
		print("Passwords do not match.\nQuitting...")
		exit()


	e = PyHide(pwd1)

	script = e.create(filename)

	with open("payload.py", "w") as o:
		o.write(script)