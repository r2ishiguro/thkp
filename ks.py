import BaseHTTPServer
import SocketServer
import urlparse
import subprocess
import re
import urllib
import urllib2
from pgpdump import AsciiData
import sys
import json

GT_URL = "http://localhost:6962/gt/v1/"

class HKPHandler(BaseHTTPServer.BaseHTTPRequestHandler):
	def do_HEAD(s):
		s.send_response(200)
		s.send_header("Content-Type", "text/html");
		s.send_header("Access-Control-Allow-Origin", "*");
		s.end_headers()
	def do_GET(s):
		s.process()
	def do_POST(s):
		s.process()
	def do_OPTIONS(s):
		s.send_response(200)
		s.send_header("Access-Control-Allow-Origin", "*");
		s.end_headers()

	def check_proof(s, kblock):
		data = AsciiData(kblock)
		for packet in data.packets():
			if packet.tag() == 17:
				packet.parse()
				print "User Attribute found: ", packet
		return 1

	def lookup(s, ss):
		p = subprocess.Popen(["/opt/local/bin/gpg", "--homedir", s.gpghome, "--export", "--armor", ss], stdout=subprocess.PIPE);
		kblock = p.stdout.read()
		if p.wait() == 0 and len(kblock) > 0:
			s.send_response(200)
			s.send_header("Content-Type", "text/html");
			s.send_header("Access-Control-Allow-Origin", "*");
			s.end_headers()
			s.wfile.write(kblock)
		else:
			s.send_response(404)
			s.send_header("Access-Control-Allow-Origin", "*");
			s.end_headers()

	def add(s, kblock):
		o = urlparse.parse_qs(kblock)
		kblock = o['keytext'][0]
		# check the email address proof
		if s.check_proof(kblock) == 0:
			return
		p = subprocess.Popen(["/opt/local/bin/gpg", "--homedir", s.gpghome, "--batch", "--no-tty", "--fast-import"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		out = p.communicate(kblock)[1]
		match = re.search(r'key\s+(\w+)', out)
		if match:
			keyid = match.group(1)
			print "signing", keyid
			ret = subprocess.call(["/opt/local/bin/gpg", "--homedir", s.gpghome, "--batch", "--sign-key", "--yes", keyid])
			if ret == 0:
				p = subprocess.Popen(["/opt/local/bin/gpg", "--homedir", s.gpghome, "--export", keyid], stdout=subprocess.PIPE)
				kblock = p.stdout.read()
				req = urllib2.Request(GT_URL + "add-leaf", kblock)
				response = urllib2.urlopen(req)
				ret = json.loads(response.read())
				s.send_response(200 if ret['status'] == 0 else 501)
				s.send_header("Access-Control-Allow-Origin", "*");
				s.end_headers()
			else:
				s.send_response(501)
				s.send_header("Access-Control-Allow-Origin", "*");
				s.end_headers()
		else:
			s.send_header("Access-Control-Allow-Origin", "*");
			s.end_headers()
			s.send_response(501)

	def getProof(s, ss):
		response = urllib2.urlopen(GT_URL + 'get-sth')
		sth = json.loads(response.read())
		response = urllib2.urlopen(GT_URL + 'get-proof-by-hash?hash=' + urllib.quote_plus(ss) + '&tree_size=' + str(sth['tree_size']))
		proof = json.loads(response.read())
		proof['tree_size'] = sth['tree_size']
		proof['timestamp'] = sth['timestamp']
		proof['sha256_root_hash'] = sth['sha256_root_hash']
		proof['tree_head_signature'] = sth['tree_head_signature']
		s.send_response(200)
		s.send_header("Content-Type", "text/html")
		s.send_header("Access-Control-Allow-Origin", "*")
		s.end_headers()
		s.wfile.write(json.dumps(proof))

	def getSTH(s):
		response = urllib2.urlopen(GT_URL + 'get-sth')
		sth = json.loads(response.read())
		s.send_response(200)
		s.send_header("Content-Type", "text/html")
		s.send_header("Access-Control-Allow-Origin", "*")
		s.end_headers()
		s.wfile.write(json.dumps(sth))

	def process(s):
		o = urlparse.urlparse(s.path)
		path = o.path
		if path == '/pks/lookup':
			q = urlparse.parse_qs(o.query)
			if 'search' in q:
				ss = q['search'][0]
			op = q['op'][0]
			if op == 'get':
				s.lookup(ss)
			elif op == 'x-get-proof':
				s.getProof(ss)
			elif op == 'x-get-sth':
				s.getSTH(ss)
			else:
				s.send_response(400)
				s.send_header("Access-Control-Allow-Origin", "*")
				s.end_headers()
		elif path == '/pks/add':
			kblock = s.rfile.read(int(s.headers['Content-Length']))
			s.add(kblock)
		else:
			s.send_response(400)
			s.send_header("Access-Control-Allow-Origin", "*")
			s.end_headers()

if __name__ == '__main__':
	port = 8000
	home = "~/.gnupg.ks"
	if len(sys.argv) > 1:
		port = int(sys.argv[1])
		if len(sys.argv) > 2:
			home = sys.argv[2]
	HKPHandler.gpghome = home
	server = BaseHTTPServer.HTTPServer
	httpd = server(('', port), HKPHandler)
	httpd.serve_forever()
