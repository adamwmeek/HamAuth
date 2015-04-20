#!/usr/bin/python

import socket
import struct
import hashlib
import hmac

import argparse

parser = argparse.ArgumentParser(description='Authenticates commands based on a OTP')
parser.add_argument('server', help='the size of the one time pad to create')
parser.add_argument('serverKey', help='a secret key used to verify the server')
parser.add_argument('password', help='the seed for the one time pad')
parser.add_argument('-p','--port', default=22222, type=int, help='port number to listen on')

server =  parser.parse_args().server
serverKey = parser.parse_args().serverKey.strip()
password = parser.parse_args().password.strip()
portNo = parser.parse_args().port


########



state = 0
sentString =''

## States:
# 0 - send string
# 1 - send password hash

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect((server, portNo))
s.settimeout(1)


while True:

	if state == 0:
		sentString = raw_input('-->')

		sentString = sentString.strip()

		buff= struct.pack('!4096s', sentString)

		s.send(buff)
		
		state = 1

	elif state == 1:
		req = s.recv(4096)
		hashS = req[0:36]


		#TODO: get HMAC from server & verify
		(padSize,issuedHMAC) = struct.unpack('!L32s', hashS)
		d = hmac.new(serverKey)
		d.update(str(padSize))
		d.update(sentString)

		correctHMAC = d.hexdigest()

		##if hmac.compare_digest(correctHMAC,issuedHMAC):
		if correctHMAC == issuedHMAC:

			#password = raw_input('Password(%d):' % padSize)
			correctHash = password

			m = hashlib.md5()
			for i in range(0,int(padSize)):
				m.update(correctHash)
				correctHash = m.hexdigest()

			hashStr = struct.pack('!32s', correctHash)
			s.send(hashStr)

		else:

			print 'WARNING: Incorrect reply from server!\nTHIS COULD BE AN ATTACK'

		state = 0
