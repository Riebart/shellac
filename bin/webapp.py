#!/usr/bin/env python

import sys
import os
import subprocess
import string
import urlparse
import shutil
import cgi
import BaseHTTPServer
import urllib
import base64
import random

try:
  import simplejson as json
except ImportError:
  import json

config_file = 'etc/shellac.json'

class Model:

  def __init__(self):
    self.new_names = []
    self.actions = None
    self.load()

  def load(self):
    self.config = json.loads(file(config_file).read())

    while len(self.new_names) < len(self.config['actions']):
      self.new_names.append("".join([ chr(random.randint(ord('a'), ord('z'))) for i in range(16) ]))
      self.new_names = list(set(self.new_names))

    if len(self.new_names) > len(self.config['actions']):
      self.new_names = self.new_names[:len(self.config['actions'])]

    self.actions = dict(zip(self.new_names, self.config['actions']))
    return self.actions

model = Model()

class HttpHandler( BaseHTTPServer.BaseHTTPRequestHandler ):

  def do_GET(self):
    if self.path == '/config/':
      actions = model.load()
      obfuscated_actions = json.dumps({'actions': {k: {'name': k, 'title': v['title'], 'contexts': v['contexts']} for k, v in actions.iteritems() }})
      self.send_response(200)
      self.send_header('Content-Type', 'application/json')
      self.send_header("Content-Length", str(len(obfuscated_actions)))
      self.end_headers()
      self.wfile.write(obfuscated_actions)
    else:
      self.send_error(404)

  def do_POST(self):

    if self.path != '/action/':
      self.send_error(404)
      return

    # Form processing

    ctype = self.headers.getheader('Content-Type','')
    ctype_params = [ s.strip().split('=') for s in ctype.split(';') ]
    ctype = ctype_params.pop(0)[0]
    ctype_params = dict(ctype_params)

    if ctype == 'application/x-www-form-urlencoded':
      clen = int(self.headers.getheader('Content-Length',0))
      body = self.rfile.read(clen)
      data = urlparse.parse_qs(body)
    elif ctype == 'multipart/form-data':
      data = cgi.parse_multipart(self.rfile, ctype_params)
    else:
      self.send_error(400)
      return

    for k, v in data.items():
      data[k] = v[0].decode('utf8')

    # Validate that action is in the config.

    actions = model.load()
    action = data.get('action','')
    action_config = actions.get(action,'')

    if action_config == '':
      self.send_error(404)
      return

    # Get the command to run. Will be interpreted by sh -c.
    shell = "/bin/sh"
    argv = [ shell, "-c", action_config['command'] ]

    utf8_vals = {}

    for key,value in data.items():
      key = key.replace(string.whitespace,"")
      key = key.replace(".","_").upper()
      key = "SHELLAC_%s" % key
      key = key.encode('utf8','ignore')

      # The selection is handled separately, so decode that from b64, then URI
      # decode it again.
      if key == "SHELLAC_INFO_SELECTIONTEXT":
        value = base64.b64decode(value)
        value = json.loads(value)
        value = map((lambda v: urllib.unquote(v)), value)
        value = "\n".join(value)
        value = value.encode("utf-8", "ignore")
        print value
      else:
        value = value.encode("utf-8", "ignore")

      # Note that putenv() doesn't support utf-8 on some platforms, so we need
      # to protect it there.
      os.environ[key] = value.decode("ascii", "ignore")
      # Also store the non-ASCII-decoded strings, for use with stdin piping
      utf8_vals[key] = value

    # For each variable listed in the 'stdin' config param, take their values
    # and concatenate them in order to be fed into the stdin of the process.
    if 'stdin' in action_config:
      stdin_text = ""
      for v in action_config['stdin']:
        stdin_text += utf8_vals[v]

      print "STDIN: " + stdin_text
      p = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
      p.stdin.write(stdin_text)
    else:
      p = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

    out, err = p.communicate()
    p.wait()

    self.send_response(200)
    if len(out) > 0 and 'return' in action_config and action_config['return'] == True:
      out = urllib.quote(out.encode("utf-8", "ignore"))
      self.send_header('Content-Type', 'text/html')
      self.send_header("Content-Length", len(out))
      self.end_headers()
      self.wfile.write(out)

def main( argv ):

  prog = argv.pop(0)
  host = '127.0.0.1'
  port = 8783

  if len(argv) >= 2:
    host, port = (argv.pop(0), int(argv.pop(0)))
  elif len(argv) == 1:
    port = int(argv.pop(0))

  print >> sys.stderr, "shellac server @ http://%s:%u/" % (host,port)

  server_address = (host, port)
  httpd = BaseHTTPServer.HTTPServer(server_address, HttpHandler)
  httpd.serve_forever()


if __name__ == '__main__':
  import sys
  main( sys.argv )
  sys.exit( 0 )

