#!/usr/bin/python

import socket
import struct
import hashlib
import hmac

import argparse

parser = argparse.ArgumentParser(description='Authenticates commands based on a OTP')
parser.add_argument('password', help='the password used to generate OTP')
parser.add_argument('serverKey', help='a secret key used to verify the server')
parser.add_argument('-s','--size', default=1024, type=int, help='the size of the one time pad to create')
parser.add_argument('-p','--port', default=22222, type=int, help='port number to listen on')

password = parser.parse_args().password.strip()
serverKey = parser.parse_args().serverKey.strip()
padSize =  parser.parse_args().size
portNo = parser.parse_args().port

########

state = 0

## States:
# 0 - waiting for string
# 1 - waiting for auth
# 2 - print string

recvStr = ''

## Initial attemp: used pre-generated hash table
## This leaves a huge (32k) chunk in memory that makes a nice target!
## This is also hopelessly large for small memory systems

#pad = []
# tempHash = password

# for i in range(padSize):
# 	m.update(tempHash)
# 	tempHash = m.hexdigest()
# 	pad.append(tempHash)

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(('', portNo))

fromAddr = ''
print 'Pad Length: %d' % padSize

#padSize = padSize - 1

while (padSize > 0):

	if state == 0:
		s.settimeout(0)
		(req,fromAddr) = s.recvfrom(4096)

		recvStr = req.split('\00',1)[0]
		#recStr = req[:recvStripIndex]

		#Generate HMAC using padSize, recvStr, serverSec
		d = hmac.new(serverKey)
		d.update(str(padSize))
		d.update(recvStr)

		hmacStr = d.hexdigest()
		
		buf = struct.pack('!L32s',padSize,hmacStr)
		s.sendto(buf,fromAddr)
		
		state = 1

	elif state == 1:
			
		print 'Got message. Waiting for auth. with key %d' % padSize
		padSize = padSize - 1
		s.settimeout(30)
		try:
			(req,fromAddr) = s.recvfrom(4096)
			hashS = req[0:32]

			## Unpack hash from client
			(hashNums,) = struct.unpack('!32s', hashS)

			## Generate correct key locally
			tempHash = password
			m = hashlib.md5()

			for i in range(0,padSize):
				m.update(tempHash)
				tempHash = m.hexdigest()

			

			#if hashNums == pad[padSize]:
			if hashNums == tempHash:
				state = 3
			else:
				print "Wanted: %s\nGot: %s" % (tempHash, hashNums)
				state = 0
		except socket.timeout:
			print 'Timed out.'
			state = 0

	elif state == 3:

		print recvStr
		state = 0
