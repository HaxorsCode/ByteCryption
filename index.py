import base64
from utils import *

def encrypt(raw: str, key: str='hanz'):
	stage_1 = ''
	stage_2 = ''
	stage_3 = ''

	for i, char in enumerate(raw):
		char = chr(ord(char) + ord(key[i % len(key) - 1]))
		stage_1 += char

	return 'e6' + base64.b64encode(stage_1.encode()).decode()

def decrypt(encrypted: str, key: str='hanz'):
	encrypted = base64.b64decode(encrypted.encode('utf8')).decode()
	stage_1 = ''

	for i, char in enumerate(encrypted):
		char = chr(ord(char) - ord(key[i % len(key) - 1]))
		stage_1 += char

	return stage_1

if __name__ == '__main__':
	import sys, os
	argv = sys.argv[1:]
	key = 'hanz'
	no_escape = False

	decrypted = ''
	encrypted = ''

	try:
		key = argv[1]
		no_escape = '-ne' in argv
	except IndexError:
		pass

	if os.path.isfile(argv[0]):
		with open(argv[0], "rb") as f:
			file_content = f.read().decode()

			if file_content.startswith('e6'):
				_encrypted = file_content[2:]
				decrypted = decrypt(_encrypted, key=key)
			else:
				encrypted = encrypt(file_content, key=key)
	else:
		if argv[0].startswith('e6'):
			_encrypted = argv[0][2:]
			decrypted = decrypt(_encrypted, key=key)
		else:
			encrypted = encrypt(argv[0], key=key)

	if no_escape:
		print((encrypted or decrypted))
	else:
		print((encrypted or decrypted).encode('unicode_escape').decode())
