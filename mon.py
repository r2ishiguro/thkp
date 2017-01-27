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
import threading
import time

TIME_INTERVAL = 10	# seconds

keyservers = {}

def add_keyserver(url):
        global keyservers
        response = urllib2.urlopen(url + '/pks/lookup?op=get&search=ks')        # should use the key ID but for now it's assumed the key server's cert can be get by 'ks'
        kblock = response.read()
        data = AsciiData(kblock)
        keyid = ""
        for packet in data.packets():
                if packet.tag() == 6:           # public key
                        packet.parse()
                        keyid = packet.key_id
        if keyid != "":
                keyservers[keyid] = url

def Monitor():
	time.sleep(TIME_INTERVAL)	# give keyserves a few seconds to start up
	# should follow the Monitor process in RFC...
	while True:
		# for now just get the latest STH
		global currentSTH
		time.sleep(TIME_INTERVAL)

class HTTPHandler(BaseHTTPServer.BaseHTTPRequestHandler):
	def do_HEAD(s):
		s.send_response(200)
		s.send_header("Content-Type", "text/html");
		s.send_header("Access-Control-Allow-Origin", "*");
		s.end_headers()
	def do_GET(s):
		o = urlparse.urlparse(s.path)
		if o.path == '/lookup':
		        q = urlparse.parse_qs(o.query)
		        if 'search' in q:
                                ss = q['search'][0]
                                if 
	def do_OPTIONS(s):
		s.send_response(200)
		s.send_header("Access-Control-Allow-Origin", "*");
		s.end_headers()

if __name__ == '__main__':
	port = 8100
        ac = len(sys.argv)
	if ac > 1:
		port = int(sys.argv[1])
                for i in range(2:ac):
                        add_keyserver(sys.argv[i])

	# run the monitor
	th = threading.Thread(target = Monitor)
	th.daemon = True
	th.start()
	server = BaseHTTPServer.HTTPServer
	httpd = server(('', port), HKPHandler)
	httpd.serve_forever()
