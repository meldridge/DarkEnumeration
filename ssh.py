#!/usr/bin/python

import sys, os, subprocess, re, time

if len(sys.argv) != 2:
    print "Usage: ssh.py <target>"
    sys.exit(0)

ip_address = str(sys.argv[1])
vulnssh = "/root/Scripts/debian_ssh_scan_v4/debian_ssh_scan_v4.py"

def keys(ip_address):
	print "moving into ./debian_ssh_scan_v4 to run script!"
	sshvuln = vulnssh + " " + ip_address
	subprocess.call(sshvuln, shell=True)

	print "Running nmap SSH scripts"
	sshnse = "nmap -sS -p22 --script ssh* %s -oA /tmp/%s/ssh-nse" % (ip_address, ip_address)
	subprocess.call(sshnse, shell=True)
  
	print "Testing for hardcoded SSH keys"
	authorized_fingerprints = "/root/git/ssh-badkeys/authorized/authorized-fingerprints.txt"
	host_fingerprints = "/root/git/ssh-badkeys/host/host-fingerprints.txt"
		
	keyscanfile = "/tmp/%s/ssh-keyscan.txt" % ip_address
	os.system("ssh-keyscan %s > %s" % (ip_address, keyscanfile))
		
	print "Checking for authorised keys:"
	os.system("ssh-keygen -l -f %s | cut -d' ' -f2 | grep %s" % (keyscanfile, authorized_fingerprints))
	print "Checking host keys:"
	os.system("ssh-keygen -l -f %s | cut -d' ' -f2 | grep %s" % (keyscanfile, host_fingerprints))

def main():
	keys(ip_address)

if __name__=='__main__':
	main()
