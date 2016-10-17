#!/usr/bin/python
import sys, os, subprocess, re, time

if len(sys.argv) != 2:
    print "Usage: ./snmp.py <target>"
    sys.exit(0)

ip_address = str(sys.argv[1])
community = ["public", "private", "manager"]

def walk(ip_address):
	print "[*] Grabbing SNMP data from " + ip_address
	snmpwalk = "snmpwalk -c public -v1 %s > /tmp/%s/snmpwalk" % (ip_address, ip_address)
	callsnmpwalk = subprocess.Popen(snmpwalk, stdout=subprocess.PIPE, shell=True)
	callsnmpwalk.wait()

def onesixtyone(ip_address):
	print "[*] Grabbing more SNMP data from " + ip_address
	for string in community:
		rgr = "onesixtyone -c %s %s > /tmp/%s/onesixtyone_%s" % (string, ip_address, ip_address, string)
		subprocess.call(rgr, shell=True)
		
def main():
	walk(ip_address)
	onesixtyone(ip_address)

if __name__=='__main__':
	main()
