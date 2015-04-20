#!/usr/bin/python

import hashlib

m = hashlib.md5()

import argparse

parser = argparse.ArgumentParser(description='Authenticates commands based on a OTP')
parser.add_argument('password', help='the password used to generate OTP')
parser.add_argument('-s','--size', default=1024, type=int, help='the size of the one time pad to create')

password = parser.parse_args().password
padSize =  parser.parse_args().size

pad = []
tempHash = password

print 'Building hash table...'
for i in range(padSize):
	m.update(tempHash)
	tempHash = m.hexdigest()
	pad.append(tempHash)
print 'done'

while True:
	hashS = raw_input('-->')

	if hashS == 'ls':
		for i in range(len(pad)):
			print pad[i]
	else:
		try:
			print 'Key place is %d' % pad.index(hashS)+1
		except:
			print 'Key not found!'
