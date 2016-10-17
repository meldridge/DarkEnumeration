#!/usr/bin/python

import sys, os, subprocess, re, time

if len(sys.argv) != 2:
    print "Usage: samba.py <target>"
    sys.exit(0)

ip_address = str(sys.argv[1])
nse_scripts = "smb-vuln-conficker.nse,smb-vuln-cve2009-3103.nse,smb-vuln-ms06-025.nse,smb-vuln-ms07-029.nse,smb-vuln-ms08-067.nse,smb-vuln-ms10-054.nse,smb-vuln-ms10-061.nse,smb-os-discovery"

def nbtscan(ip_address):
	print "[*] Grabbing generic data from " + ip_address
	smbscan = "nbtscan -r %s > /tmp/%s/nbtscan" % (ip_address, ip_address)
	callsmbscan = subprocess.Popen(smbscan, stdout=subprocess.PIPE, shell=True)
	callsmbscan.wait()

def sharenum(ip_address):
	print "[*] Grabbing generic SHARE data from " + ip_address
	sharescan = "enum4linux -S %s > /tmp/%s/enum4linux_share" % (ip_address, ip_address)
	callsharescan = subprocess.Popen(sharescan, stdout=subprocess.PIPE, shell=True)
	callsharescan.wait()

def userenum(ip_address):
	print "[*] Grabbing generic SHARE data from " + ip_address
	userscan = "enum4linux -U %s > /tmp/%s/enum4linux_users" % (ip_address, ip_address)
	callsharescan = subprocess.Popen(userscan, stdout=subprocess.PIPE, shell=True)
	callsharescan.wait()

def nmap(ip_address):
	print "[*] Running non-default NSE scripts against " + ip_address		
	smbnse = "nmap -sTU -pT:139,445,U:139 --script %s --script-args unsafe=1 %s -oA /tmp/%s/smb_nse" % (nse_scripts, ip_address, ip_address)
	print "[*] nmap command: " + smbnse
	subprocess.call(smbnse, shell=True)

def main():
#	nbtscan(ip_address)
#	sharenum(ip_address)
#	userenum(ip_address)
	nmap(ip_address)

if __name__=='__main__':
	main()
