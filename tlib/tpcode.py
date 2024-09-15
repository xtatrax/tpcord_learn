# -*- coding: utf-8 -*-

############################################################
# file : tpcord.py
# 制作 ： tatra 2024年9月14日
#
# 暗号化とかの勉強用
#
# 対象バージョン : python 3.x 
# 外部モジュール : pycryptodome
# pip install pycryptodome
#
# 外部ソフト :
#
# メモ :
#	参考、引用元
#	->https://qiita.com/takafi/items/5656426ec1df62e22689
#
############################################################

import os
import hashlib
import joblib
from Crypto.Cipher import AES
from pathlib import Path
version=b'00.01.01'

class tpcord():

	def __init__(self):
		self.___default_key = os.path.normpath(os.path.join(Path.home(),".config/code/default_key.data"))
		self.___crypt_list = ['salt', 'cipher_text', 'header', 'nonce', 'tag']
		self.___salt_byte = 32
		self.___header=[
			bytes.fromhex("F0 0F 1A 0D 0A 1F 24 0A"),
			b'\xe0\xa2l\xac\xa2T\x1bbs\xf4\x00oM\x1e\xa1a\xc4(\xc7X\x1c\xb7UC\xd7\xdas\x86\xc1\x11\xdcE'
			b'ver.',version
		]

		if os.path.exists(self.___default_key):
			self.___lead_default_key()


	def encrypt(self, message, password, header=None):
		salt = os.urandom(self.___salt_byte)
		# 調べる n=2**14, r=8, p=1, dklen=32 について
		key = hashlib.scrypt(password=password, salt=salt, n=2**14, r=8, p=1, dklen=32)
		cipher = AES.new(key, AES.MODE_GCM)

		if header :
			cipher.update(header)

		cipher_text, tag = cipher.encrypt_and_digest(message)
		return [salt, cipher_text, header, cipher.nonce, tag]

	def decrypt(self,encrypted_message, password):
		salt, cipher_text, header, nonce, tag = encrypted_message
		key = hashlib.scrypt(password=password, salt=salt, n=2**14, r=8, p=1, dklen=32)
		cipher = AES.new(key, AES.MODE_GCM, nonce)

		if header:
			cipher.update(header)

		return cipher.decrypt_and_verify(cipher_text, tag)


	def ___create_default_key(self):
		{}

	def ___lead_default_key(self):
		{}