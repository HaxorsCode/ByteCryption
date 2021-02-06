import base64
from utils import *

def encrypt(raw: str, key: str='hanz'):
	stage_1 = ''
	stage_2 = ''
	stage_3 = ''

	for char in raw:
		char = chr(ord(char) + ord(key[raw.index(char) % len(key)]))
		stage_1 += char

	return 'e6' + base64.b64encode(stage_1.encode()).decode()

def decrypt(encrypted: str, key: str='hanz'):
	encrypted = base64.b64decode(encrypted.encode('utf8')).decode()
	stage_1 = ''

	for char in encrypted:
		char = chr(ord(char) - ord(key[encrypted.index(char) % len(key)]))
		stage_1 += char

	return stage_1

if __name__ == '__main__':
	import sys
	argv = sys.argv[1:]
	key = 'hanz'

	try:
		key = argv[1]
	except IndexError:
		pass

	if argv[0].startswith('e6'):
		encrypted = argv[0][2:]
		decrypted = decrypt(encrypted, key=key)
		print(decrypted.encode('unicode_escape'))
	else:
		encrypted = encrypt(argv[0], key=key)
		print(encrypted.encode('unicode_escape'))
