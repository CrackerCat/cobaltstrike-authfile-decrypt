#!/usr/bin/env python3

from argparse import ArgumentParser
from gzip import decompress
from datetime import datetime
from Crypto.PublicKey import RSA
from Crypto.Util.number import bytes_to_long
from Crypto.Util.number import long_to_bytes
from binascii import hexlify

def get_args():
	parser = ArgumentParser()
	
	parser.add_argument(
		'-p',
		dest='pubkey',
		help='Cobalt Strike\'s authkey.pub (see .jar file resources)',
		default="authkey.pub"
	)

	parser.add_argument(
		'-a',
		dest='authfile',
		help='Cobalt Strike\'s .auth file',
		default="cobaltstrike.auth"
	)

	args = parser.parse_args()
	return args

def decrypt(pubkey, authfile):
	with open(pubkey, 'rb') as f:
		key = RSA.importKey(f.read())

	with open(authfile, 'rb') as f:
		ciphertext = bytes_to_long(f.read())

	plaintext = long_to_bytes(
		pow(ciphertext, key.e, key.n)
	)
	
	unpadded = unpad(plaintext)
	header = unpadded[:4]
	data_len = int.from_bytes(unpadded[5:6], byteorder="big")
	gzip_lic = unpadded[6:6+data_len]
	return header, gzip_lic

def unpad(padded):
	unpadded = b'\x00'.join(padded.split(b'\x00')[1:])
	return unpadded

def decode_license(gzip_lic):
	lic = decompress(gzip_lic).decode().split(',')
	key 		= lic[0]
	end 		= datetime.strptime(lic[1], '%y%m%d')
	watermark 	= int(lic[2])
	issued		= datetime.fromtimestamp(int(lic[3]) / 1000)

	license = {
		'key'		: key,
		'end'		: end,
		'watermark'	: watermark,
		'issued'	: issued
	}

	return license

#b'\x00\x03\x0e\x1d \x12\x96\xeaD ( \x10 \x1b\xe5\xbeR\xc6%\\3U\x8e\x8a\x1c\xb6g\xcb\x06'

def decode_license40(gzip_lic):
	lic 		= gzip_lic
	end			= datetime.strptime(str(int.from_bytes(lic[0:4], byteorder="big")), '%y%m%d')
	watermark	= hexlify(lic[4:8]).decode()
	version		= lic[8]
	readlen		= lic[9]
	key			= hexlify(lic[10:10+readlen]).decode()

	license = {
		'key'		: key,
		'end'		: end,
		'watermark'	: watermark,
		'version'	: version
	}

	return license

def print_license(license):
	print ('=== Cobalt Strike auth file details ===')
	print('Key:\t\t{0}'.format(license['key']))
	print('End date:\t{0}'.format(license['end'].strftime('%b %d %Y')))
	print('Watermark:\t{0}'.format(license['watermark']))
	if license['version']:
		print('Version:\t{0}'.format(license['version']))
	else:
		print('Issued at:\t{0}'.format(license['issued'].strftime('%b %d %Y %H:%M:%S')))

def main():
	args = get_args()
	header, gzip_lic = decrypt(args.pubkey, args.authfile)

	if header != b'\xca\xfe\xc0\xbb' and header != b'\xca\xfe\xc0\xd3':
		print('Invalid header!')
		exit(1)

	if header == b'\xca\xfe\xc0\xd3':
		license = decode_license40(gzip_lic)
	else:
		license = decode_license(gzip_lic)
	print_license(license)

if __name__ == '__main__':
	main()
