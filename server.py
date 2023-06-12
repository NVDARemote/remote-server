from twisted.internet.protocol import Protocol, Factory, defer
from twisted.python.modules import getModule
from twisted.python import log
from twisted.internet import ssl, reactor
from twisted.protocols.basic import LineReceiver
from twisted.internet.task import LoopingCall
from twisted.python import usage
from twisted.protocols.haproxy._wrapper import HAProxyWrappingFactory
from collections import OrderedDict
from logging import getLogger
logger = getLogger('remote-server')


import json
import os
import sys
from OpenSSL import crypto
import io

PING_INTERVAL = 300
INITIAL_TIMEOUT = 30
#Expiration time for generated keys, in seconds
GENERATED_KEY_EXPIRATION_TIME = 60*60*24 #One day
import time
import random
import string
import base64

class Channel(object):

	def __init__(self, key, server_state=None):
		self.clients = OrderedDict()
		self.key = key
		self.server_state = server_state

	def add_client(self, client):
		if client.protocol.protocol_version == 1:
			ids = [c.user_id for c in self.clients.values()]
			msg = dict(type='channel_joined', channel=self.key, user_ids=ids, origin=client.user_id)
		else:
			clients = [i.as_dict() for i in self.clients.values()]
			msg = dict(type='channel_joined', channel=self.key, origin=client.user_id, clients=clients)
		client.send(**msg)
		for existing_client in self.clients.values():
			if existing_client.protocol.protocol_version == 1:
				existing_client.send(type='client_joined', user_id=client.user_id)
			else:
				existing_client.send(type='client_joined', client=client.as_dict())
		self.clients[client.user_id] = client

	def remove_connection(self, con):
		if con.user_id in self.clients:
			del self.clients[con.user_id]
		for client in self.clients.values():
			if client.protocol.protocol_version == 1:
				client.send(type='client_left', user_id=con.user_id)
			else:
				client.send(type='client_left', client=con.as_dict())
		if not self.clients:
			self.server_state.remove_channel(self.key)

	def ping_clients(self):
		self.send_to_clients({'type': 'ping'})

	def send_to_clients(self, obj, exclude=None, origin=None):
		for client in self.clients.values():
			if client is exclude:
				continue
			client.send(origin=origin, **obj)

class Handler(LineReceiver):
	delimiter = b'\n'
	connection_id = 0
	MAX_LENGTH = 20*1048576

	def __init__(self):
		self.connection_id = Handler.connection_id + 1
		Handler.connection_id += 1
		self.protocol_version = 1

	def connectionMade(self):
		logger.info("Connection %d from %s" % (self.connection_id, self.transport.getPeer()))
		self.transport.setTcpNoDelay(True)
		self.bytes_sent = 0
		self.bytes_received = 0
		self.user = User(protocol=self)
		self.cleanup_timer = reactor.callLater(INITIAL_TIMEOUT, self.cleanup)
		self.user.send_motd()

	def connectionLost(self, reason):
		logger.info("Connection %d lost, bytes sent: %d received: %d" % (self.connection_id, self.bytes_sent, self.bytes_received))
		self.user.connection_lost()
		if self.cleanup_timer is not None and not self.cleanup_timer.cancelled:
			self.cleanup_timer.cancel()

	def lineReceived(self, line):
		self.bytes_received += len(line)
		try:
			parsed = json.loads(line)
			if not isinstance(parsed, dict):
				raise ValueError
		except ValueError:
			logger.warn("Unable to parse %r" % line)
			self.transport.loseConnection()
			return
		if 'type' not in parsed:
			logger.warning("Invalid object received: %r" % parsed)
			return
		parsed.pop('origin', None) #Remove an existing origin, we know where the message comes from.
		if self.user.channel is not None:
			self.user.channel.send_to_clients(parsed, exclude=self.user, origin=self.user.user_id)
			return
		elif not hasattr(self, "do_"+parsed['type']):
			logger.warning("No function for type %s" % parsed['type'])
			return
		getattr(self, "do_"+parsed['type'])(parsed)

	def do_join(self, obj):
		if 'channel' not in obj or not obj['channel']:
			self.send(type='error', error='invalid_parameters')
			return
		self.user.join(obj['channel'], connection_type=obj.get('connection_type'))
		self.cleanup_timer.cancel()

	def do_protocol_version(self, obj):
		if 'version' not in obj:
			return
		self.protocol_version = obj['version']

	def do_generate_key(self, obj):
		self.user.generate_key()

	def send(self, origin=None, **msg):
		if self.protocol_version > 1 and origin:
			msg['origin'] = origin
		obj = json.dumps(msg).encode('ascii')
		self.bytes_sent += len(obj)
		self.sendLine(obj)

	def cleanup(self):
		logger.info("Connection %d timed out" % self.connection_id)
		self.transport.abortConnection()
		self.cleanup_timer = None

class User(object):
	user_id = 0

	def __init__(self, protocol):
		self.protocol = protocol
		self.channel = None
		self.server_state = self.protocol.factory.server_state
		self.connection_type = None
		self.user_id = User.user_id + 1
		User.user_id += 1

	def as_dict(self):
		return dict(id=self.user_id, connection_type=self.connection_type)

	def generate_key(self):
		ip = self.protocol.transport.getPeer().host
		if ip in self.server_state.generated_ips and time.time()-self.server_state.generated_ips[ip] < 1:
			self.send(type="error", message="too many keys")
			self.protocol.transport.loseConnection()
			return
		key = "".join([random.choice(string.digits) for i in range(7)])
		while key in self.server_state.generated_keys or key in self.server_state.channels.keys():
			key = "".join([random.choice(string.digits) for i in range(7)])
		self.server_state.generated_keys.add(key)
		self.server_state.generated_ips[ip] = time.time()
		reactor.callLater(GENERATED_KEY_EXPIRATION_TIME, lambda: self.server_state.generated_keys.remove(key))
		if key:
			self.send(type="generate_key", key=key)
		return key

	def connection_lost(self):
		if self.channel is not None:
			self.channel.remove_connection(self)

	def join(self, channel, connection_type):
		if self.channel:
			self.send(type="error", error="already_joined")
			return
		self.connection_type = connection_type
		self.channel = self.server_state.find_or_create_channel(channel)
		self.channel.add_client(self)

	def do_generate_key(self):
		key = self.generate_key()
		if key:
			self.send(type="generate_key", key=key)

	def send(self, **obj):
		self.protocol.send(**obj)

	def send_motd(self):
		if self.server_state.motd is not None:
			self.send(type='motd', motd=self.server_state.motd)

class RemoteServerFactory(Factory):
	def __init__(self, server_state):
		self.server_state = server_state

	def ping_connected_clients(self):
		for channel in self.server_state.channels.values():
			channel.ping_clients()

class ServerState(object):

	def __init__(self):
		self.channels = {}
		#Set of already generated keys
		self.generated_keys = set()
		#Dictionary of ips to generated time for people who have generated keys.
		self.generated_ips = {}

	def remove_channel(self, channel):
		del self.channels[channel]

	def find_or_create_channel(self, name):
		if name in self.channels:
			channel = self.channels[name]
		else:
			channel = Channel(name, self)
			self.channels[name] = channel
		return channel

class Options(usage.Options):
	optParameters = [
		["certificate", "c", "cert", "SSL certificate"],
		["privkey", "k", "privkey", "SSL private key"],
		["chain", "C", "chain", "SSL chain"],
		["motd", "m", "motd", "MOTD"],
		["network-interface", "i", "::", "Interface to listen on"],
		["port", "p", "6837", "Server port"],
	]
	optFlags = [
		["no-ssl", "n", "Disable SSL"],
	]

def main():
	config = Options()
	config.parseOptions()
	log.startLogging(sys.stdout)
	if not config['no-ssl']:
		privkey = open(config['privkey']).read()
		certData = open(config['certificate']).read()
		chain = open(config['chain']).read()
		privkey = crypto.load_privatekey(crypto.FILETYPE_PEM, privkey)
		certificate = crypto.load_certificate(crypto.FILETYPE_PEM, certData)
		chain = crypto.load_certificate(crypto.FILETYPE_PEM, chain)
		context_factory = ssl.CertificateOptions(privateKey=privkey, certificate=certificate, extraCertChain=[chain])
	state = ServerState()
	if os.path.exists(config['motd']):
		with io.open(config['motd'], encoding='utf-8') as fp:
			state.motd = fp.read().strip()
	else:
		state.motd = None
	f = RemoteServerFactory(state)
	wrapped = HAProxyWrappingFactory(f)
	l = LoopingCall(f.ping_connected_clients)
	l.start(PING_INTERVAL)
	f.protocol = Handler
	if config['no-ssl']:
		reactor.listenTCP(int(config['port']), wrapped, interface=config['network-interface'])
	else:
		reactor.listenSSL(int(config['port']), f, context_factory, interface=config['network-interface'])
	reactor.run()
	return defer.Deferred()

if __name__ == '__main__':
	res = main()
