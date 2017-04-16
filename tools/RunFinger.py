#!/usr/bin/env python
# This file is part of Responder, a network take-over set of tools 
# created and maintained by Laurent Gaffie.
# email: laurent.gaffie@gmail.com
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>

#built-in modules
import platform
import re
import sys
import socket
import struct
import datetime
import multiprocessing
import Queue
import threading
import optparse
import time
import signal
import json

#project modules
from odict import OrderedDict

#3rd party modules
if platform.python_version()[0] == '2':
	try:
		import ipaddress
	except:
		print '[!] The following module is not installed: ipaddress \r\n this is a module for python 3 but official backport is available as py2-ipaddress'
		sys.exit()
		
else:
	import ipaddress

__version__ = "0.7a"


class Packet():
		fields = OrderedDict([])
		def __init__(self, **kw):
				self.fields = OrderedDict(self.__class__.fields)
				for k,v in kw.items():
						if callable(v):
								self.fields[k] = v(self.fields[k])
						else:
								self.fields[k] = v
		def __str__(self):
				return "".join(map(str, self.fields.values()))

def longueur(payload):
		length = struct.pack(">i", len(''.join(payload)))
		return length

def GetBootTime(data):
		Filetime = int(struct.unpack('<q',data)[0])
		t = divmod(Filetime - 116444736000000000, 10000000)
		time = datetime.datetime.fromtimestamp(t[0])
		return time, time.strftime('%Y-%m-%d %H:%M:%S')

class SMBHeader(Packet):
		fields = OrderedDict([
				("proto",	  "\xff\x53\x4d\x42"),
				("cmd",		"\x72"),
				("error-code", "\x00\x00\x00\x00" ),
				("flag1",	  "\x00"),
				("flag2",	  "\x00\x00"),
				("pidhigh",	"\x00\x00"),
				("signature",  "\x00\x00\x00\x00\x00\x00\x00\x00"),
				("reserved",   "\x00\x00"),
				("tid",		"\x00\x00"),
				("pid",		"\x00\x00"),
				("uid",		"\x00\x00"),
				("mid",		"\x00\x00"),
		])

class SMBNego(Packet):
		fields = OrderedDict([
				("Wordcount", "\x00"),
				("Bcc", "\x62\x00"),
				("Data", "")
		])
		
		def calculate(self):
				self.fields["Bcc"] = struct.pack("<h",len(str(self.fields["Data"])))

class SMBNegoData(Packet):
		fields = OrderedDict([
				("BuffType","\x02"),
				("Dialect", "NT LM 0.12\x00"),
		])


class SMBSessionFingerData(Packet):
		fields = OrderedDict([
				("wordcount", "\x0c"),
				("AndXCommand", "\xff"),
				("reserved","\x00" ),
				("andxoffset", "\x00\x00"),
				("maxbuff","\x04\x11"),
				("maxmpx", "\x32\x00"),
				("vcnum","\x00\x00"),
				("sessionkey", "\x00\x00\x00\x00"),
				("securitybloblength","\x4a\x00"),
				("reserved2","\x00\x00\x00\x00"),
				("capabilities", "\xd4\x00\x00\xa0"),
				("bcc1","\xb1\x00"), #hardcoded len here and hardcoded packet below, no calculation, faster.
				("Data","\x60\x48\x06\x06\x2b\x06\x01\x05\x05\x02\xa0\x3e\x30\x3c\xa0\x0e\x30\x0c\x06\x0a\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a\xa2\x2a\x04\x28\x4e\x54\x4c\x4d\x53\x53\x50\x00\x01\x00\x00\x00\x07\x82\x08\xa2\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x05\x01\x28\x0a\x00\x00\x00\x0f\x00\x57\x00\x69\x00\x6e\x00\x64\x00\x6f\x00\x77\x00\x73\x00\x20\x00\x32\x00\x30\x00\x30\x00\x32\x00\x20\x00\x53\x00\x65\x00\x72\x00\x76\x00\x69\x00\x63\x00\x65\x00\x20\x00\x50\x00\x61\x00\x63\x00\x6b\x00\x20\x00\x33\x00\x20\x00\x32\x00\x36\x00\x30\x00\x30\x00\x00\x00\x57\x00\x69\x00\x6e\x00\x64\x00\x6f\x00\x77\x00\x73\x00\x20\x00\x32\x00\x30\x00\x30\x00\x32\x00\x20\x00\x35\x00\x2e\x00\x31\x00\x00\x00\x00\x00"),
		])

##Now Lanman
class SMBHeaderLanMan(Packet):
		fields = OrderedDict([
				("proto", "\xff\x53\x4d\x42"),
				("cmd", "\x72"),
				("error-code", "\x00\x00\x00\x00" ),
				("flag1", "\x08"),
				("flag2", "\x01\xc8"),
				("pidhigh", "\x00\x00"),
				("signature", "\x00\x00\x00\x00\x00\x00\x00\x00"),
				("reserved", "\x00\x00"),
				("tid", "\x00\x00"),
				("pid", "\x3c\x1b"),
				("uid", "\x00\x00"),
				("mid", "\x00\x00"),
		])

#We grab the domain and hostname from the negotiate protocol answer, since it is in a Lanman dialect format.
class SMBNegoDataLanMan(Packet):
		fields = OrderedDict([
				("Wordcount", "\x00"),
				("Bcc", "\x0c\x00"),#hardcoded len here and hardcoded packet below, no calculation, faster.
				("BuffType","\x02"),
				("Dialect", "NT LM 0.12\x00"),

		])

#####################

def connect_target(target, timeout = 2):
	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.settimeout(timeout)
		s.connect(target)
		return s
	except Exception as e:
		raise

def IsSigningEnabled(data): 
	if data[39] == "\x0f":
		return True
	else:
		return False

def atod(a): 
	return struct.unpack("!L",inet_aton(a))[0]

def dtoa(d): 
	return inet_ntoa(struct.pack("!L", d))

def OsNameClientVersion(data):
	try:
		length = struct.unpack('<H',data[43:45])[0]
		if length > 255:
			OsVersion, ClientVersion = tuple([e.replace('\x00','') for e in data[48+length:].split('\x00\x00\x00')[:2]])
			return OsVersion, ClientVersion
		if length <= 255:
			OsVersion, ClientVersion = tuple([e.replace('\x00','') for e in data[47+length:].split('\x00\x00\x00')[:2]])
			return OsVersion, ClientVersion
	except:
		return "Could not fingerprint Os version.", "Could not fingerprint LanManager Client version"
def GetHostnameAndDomainName(data):
	try:
		DomainJoined, Hostname = tuple([e.replace('\x00','') for e in data[81:].split('\x00\x00\x00')[:2]])
		Time = GetBootTime(data[60:68])
		#If max length domain name, there won't be a \x00\x00\x00 delineator to split on
		if Hostname == '':
			DomainJoined = data[81:110].replace('\x00','')
			Hostname = data[113:].replace('\x00','')
		return Hostname, DomainJoined, Time
	except:
		return "Could not get Hostname.", "Could not get Domain joined"

def DomainGrab(target, timeout = 2):
	try:
		s = connect_target(target, timeout)
		h = SMBHeaderLanMan(cmd="\x72",mid="\x01\x00",flag1="\x00", flag2="\x00\x00")
		n = SMBNegoDataLanMan()
		packet0 = str(h)+str(n)
		buffer0 = longueur(packet0)+packet0
		s.sendall(buffer0)
		data = s.recv(2048)
		s.close()
		if data[8:10] == "\x72\x00":
			return GetHostnameAndDomainName(data)
	except:
		raise

def unhook_sginals(signal, frame):
	return

def SmbFinger(target, timeout = 2):
	try:
		s = connect_target(target, timeout)
		h = SMBHeader(cmd="\x72",flag1="\x18",flag2="\x53\xc8")
		n = SMBNego(Data = SMBNegoData())
		n.calculate()
		packet0 = str(h)+str(n)
		buffer0 = longueur(packet0)+packet0
		s.sendall(buffer0)
		data = s.recv(2048)
		signing = IsSigningEnabled(data)
		if data[8:10] == "\x72\x00":
			head = SMBHeader(cmd="\x73",flag1="\x18",flag2="\x17\xc8",uid="\x00\x00")
			t = SMBSessionFingerData()
			packet0 = str(head)+str(t)
			buffer1 = longueur(packet0)+packet0  
			s.send(buffer1) 
			data = s.recv(2048)
			s.close()
		if data[8:10] == "\x73\x16":
			OsVersion, ClientVersion = OsNameClientVersion(data)
			return signing, OsVersion, ClientVersion
	except:
		raise

class LogEntry():
	DEBUG		= 0
	INFO		= 1
	WARNING		= 2
	EXCEPTION	= 3
	ERROR		= 4
	def __init__(self, level, source, msg):
		self.timestamp = datetime.datetime.utcnow()
		self.level	= level
		self.source	= source
		self.msg	= msg
		
	def getLevel(self):
		if self.level == LogEntry.DEBUG:
			return 'DEBUG'
		elif self.level == LogEntry.INFO:
			return 'INFO'
		elif self.level == LogEntry.WARNING:
			return 'WARNING'
		elif self.level == LogEntry.EXCEPTION:
			return 'EXCEPTION'
		elif self.level == LogEntry.ERROR:
			return 'ERROR'

class SMBTarget():
	def __init__(self, target, port = 445):
		self.address      = (target,port)
		self.hostname     = ''
		self.domainJoined = ''
		self.time         = ''
		self.signing      = ''
		self.OsVer        = ''
		self.LanManClient = ''
		
		self.isScanned    = False
		self.scantime     = datetime.datetime.utcnow()
		self.scanresult   = ''
		self.scanfail_reason = ''
	
	def toDict(self):
		t = {}
		t['address']      = self.address
		t['hostname']     = self.hostname
		t['domainJoined'] = self.domainJoined
		if self.time != '':
			t['time'] = self.time[0].isoformat()
		else:
			t['time'] = ''
		t['signing']      = self.signing
		t['OsVer']        = self.OsVer
		t['LanManClient'] = self.LanManClient
		t['isScanned']    = self.isScanned
		t['scantime']     = self.scantime.isoformat()
		t['scanresult']   = self.scanresult
		t['scanfail_reason'] = self.scanfail_reason
		return t

class AddrGen(multiprocessing.Process):
	def __init__(self, iprange,scanQueue, resultQueue, config, startip = ''):
		multiprocessing.Process.__init__(self)
		self.resultQueue = resultQueue
		self.iprange	= unicode(iprange)
		self.scanQueue	= scanQueue
		self.config		= config
		self.startip	= unicode(startip)
		self.startctr	= 0
		

	def log(self, level, msg):
		self.resultQueue.put(LogEntry(level, self.name, msg))
		
	def run(self):
		signal.signal(signal.SIGINT, unhook_sginals)
		
		if self.iprange.find('/') == -1:
			try:
				ipaddress.ip_address(self.iprange)
				self.scanQueue.put(SMBTarget(self.iprange))
			except Exception as e:
				self.log(LogEntry.EXCEPTION, str(e))
				pass
		else:
			try:
				try:
					if self.startip != '':
						if ipaddress.ip_address(self.startip) in ipaddress.ip_network(self.iprange, strict=False):
							self.startctr = int(socket.inet_aton(str(self.startip)).encode('hex'),16) - int(socket.inet_aton(str(ipaddress.ip_network(self.iprange, strict=False)[0])).encode('hex'),16)
							self.log(LogEntry.DEBUG,'Starting at: ' + str(self.startctr))
						else:
							self.log(LogEntry.WARNING,'Start IP address is not part of the IP range supplied!')
				except Exception as e:
					self.log(LogEntry.WARNING, 'Failed to convert starting IP! Reason: ' + str(e))
					pass
			
				ctr = 0
				for ip in ipaddress.ip_network(self.iprange, strict=False):
					ctr += 1
					if ctr > self.startctr:
						self.scanQueue.put(SMBTarget(str(ip)))
			except:
				self.log(LogEntry.EXCEPTION, 'Ip range error!')
				pass
		
		for i in xrange(self.config['processCount'] * self.config['threadCount']):
			self.scanQueue.put('')

		self.log(LogEntry.DEBUG, 'AddrGen exhausted all ip addresses! Terminating.')

class SMBFinger(multiprocessing.Process):
	def __init__(self, scanQueue, resultQueue, config):
		multiprocessing.Process.__init__(self)
		self.scanQueue = scanQueue
		self.resultQueue = resultQueue
		self.fingerthreads = []
		
		self.config = config
		
	def log(self, level, msg):
		self.resultQueue.put(LogEntry(level, self.name, msg))

	def run(self):
		self.log(LogEntry.DEBUG, 'SMBFinger running!')
		signal.signal(signal.SIGINT, unhook_sginals)
		for i in xrange(self.config['threadCount']):
			t = threading.Thread(target=self.threadedfinger, args=())
			t.daemon = True
			self.fingerthreads.append(t)
			t.start()
			
		for t in self.fingerthreads:
			t.join()
				
		self.log(LogEntry.DEBUG,'Stopped! Terminating.')
		return
		
	def threadedfinger(self):
		self.log(LogEntry.DEBUG,'threadedfinger running!')
		while True:
			target = self.scanQueue.get()
			
			if target == '':
				self.resultQueue.put('')
				self.log(LogEntry.DEBUG,'Reached the end of the Queue! Terminating.')
				return
			
			self.resultQueue.put(self.finger(target))
		return
		
	def finger(self, target):
		try:
			self.log(LogEntry.DEBUG,"Retrieving information for %s..."%target.address[0])
			#testing connection
			connect_target(target.address)
			#fingering
			target.hostname, target.domainJoined, target.time = DomainGrab(target.address, self.config['Timeout'])
			target.signing, target.OsVer, target.lanManClient = SmbFinger(target.address, self.config['Timeout'])
			target.isScanned = True
			target.scanresult = 'OK'
			return target
		except Exception as e:
			#self.log(LogEntry.EXCEPTION, 'Scanning error occured, skipping host ' + target.address[0])
			target.isScanned = True
			target.scanresult = 'FAIL'
			target.scanfail_reason = 'Scanning error. Data:' + str(e)
			return target


class ResultProcess(multiprocessing.Process):
	def __init__(self, resultQueue, config):
		multiprocessing.Process.__init__(self)
		self.resultQueue = resultQueue
		self.config = config
		self.stopctr = 0
		self.buff = []
		self.buffsize = 1000
		self.statuscntsize = 255
		self.statuscnt = 0
		
	def log(self, level, msg):
		self.do_log(LogEntry(level, self.name, msg))

	def run(self):
		signal.signal(signal.SIGINT, unhook_sginals)

		while True:
			try:
				target = self.resultQueue.get()
			
				if target == '':
					self.stopctr += 1
					if self.stopctr == (self.config['processCount'] * self.config['threadCount']):
						self.log(LogEntry.DEBUG, 'Reached the end of the Queue! Terminating.')
						return
					continue
					
				if isinstance(target, LogEntry):
					self.do_log(target)
					continue
					

				if not target.isScanned:
					#how is this possible? :S
					continue
					
				self.statuscnt+= 1
				if self.statuscnt >= self.statuscntsize:
					self.log(LogEntry.INFO,'[SCANSATUS]%s Current IP: %s' % (self.statuscnt, target.address[0]))
					self.statuscnt = 0

				if self.config['outputFileName'] != '':
					self.buff.append(target)
					if len(self.buff) > self.buffsize:
						for t in self.buff:
							with open(self.config['outputFileName'] ,'ab') as f:
								json.dump(t.toDict(), f)
								f.write('\r\n')
						self.buff = []

					
				if target.scanresult != 'OK':
					continue

				self.ShowSmallResults(target)

			except Exception as e:
				print '[-] Exception in ResultProcess! You will not see logs now.. ' + str(e)
				self.log(LogEntry.EXCEPTION, 'jajj')
				if self.config['outputFileName'] != '':
					self.outputFile.close() 


	def ShowSmallResults(self,target):
		messge = "[SMBRESULT]['%s', Os:'%s', Domain:'%s', Signing:'%s', Time:'%s']"%(target.address[0], target.OsVer,target.domainJoined, target.signing, target.time[1])
		self.log(LogEntry.INFO,messge)

	def do_log(self, log):
		if log.level >= self.config['logLevel']:
			print '[%s][%s] [%s] %s' % (log.timestamp.isoformat(), log.source, log.getLevel(), log.msg)
	
if __name__ == '__main__':

	parser = optparse.OptionParser(usage='python %prog -i 10.10.10.224\nor:\npython %prog -i 10.10.10.0/24', version=__version__, prog=sys.argv[0])
	parser.add_option('-i','--ip', action="store", help="Target IP address or class C", dest="TARGET", metavar="10.10.10.224", default=None)
	parser.add_option('-g','--grep', action="store_true", dest="Grep", default=False, help="Output in grepable format")
	parser.add_option('-p','--processes', action="store", dest="processCount", help="Parallelism count", default=1)
	parser.add_option('-v','--verbose', action="store_true", dest="verbose", help="increases verbosity", default=False)
	parser.add_option('-s','--startip', action="store", dest="startip", help="specifies the first ip to start network scanning with.", default='')
	parser.add_option('-f','--fileout', action="store", dest="filename", help="Output results to target file in JSON format", default='')
	options, args = parser.parse_args()

	loglevel = LogEntry.INFO
	if options.verbose:
		loglevel = LogEntry.DEBUG

	if options.TARGET is None:
		print "\n-i Mandatory option is missing, please provide a target or target range.\n"
		parser.print_help()
		exit(-1)
	
		
	startip = options.startip

	processCount = int(options.processCount)
	
	threadCount = 1
	if str(options.TARGET).find('/') != -1:
		threadCount = 30
		
	totalProcessCnt = processCount + 2

	iprange = str(options.TARGET)
	config = {}
	config['Timeout'] = 0.5
	config['Grep'] = bool(options.Grep)
	config['threadCount'] = threadCount
	config['processCount'] = processCount
	config['logLevel'] = loglevel
	config['outputFileName'] = options.filename
	
	scanQueue   = multiprocessing.Queue(maxsize = 10000)
	resultQueue = multiprocessing.Queue(maxsize = 10000)
	
	rp = ResultProcess(resultQueue, config)
	rp.daemon = True
	rp.start()

	print '[+] Starting the processes'
	
	ag = AddrGen(iprange, scanQueue, resultQueue, config, startip = startip)
	ag.daemon = True
	ag.start()

	fingers = []
	for i in xrange(processCount):
		ft = SMBFinger(scanQueue, resultQueue, config)
		ft.daemon = True
		fingers.append(ft)
		ft.start()
		
	try:
		while True:
			time.sleep(1)
			cnt = 0
			if not ag.is_alive() and not rp.is_alive():
				cnt += 2
			for fin in fingers:
				if not fin.is_alive():
					cnt += 1		
			
			if cnt == totalProcessCnt:
				break
			
		print 'Scan finished!'
	except (KeyboardInterrupt, SystemExit):
		##Then exit
		sys.exit("\rExiting...")
