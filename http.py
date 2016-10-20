#!/usr/bin/python

import sys, os, subprocess, re, time

if len(sys.argv) != 2:
    print "Usage: ./http.py <target>"
    sys.exit(0)

ip_address = str(sys.argv[1])
url =  "http://" + ip_address

dirblist = ["/usr/share/dirb/wordlists/big.txt", "/usr/share/dirb/wordlists/vulns/cgis.txt"]
wfuzzlist = ["/usr/share/wfuzz/wordlist/general/big.txt", "/usr/share/wfuzz/wordlist/vulns/cgis.txt"]

def dirb(url):
	print "[!] Starting dirb scan for " + url
	for wordlist in dirblist:
		if ("big" in wordlist):
			outfile = "-o " + "/tmp/" + ip_address + "/dirb_http_big.txt"
			dirb = "dirb " + str(url) + " " + str(wordlist) + " " + str(outfile) + " -r"
			subprocess.call(dirb, shell=True)
		elif ("cgis" in wordlist):
			time.sleep(30)
			outfile2 = "-o " + "/tmp/" + ip_address + "/dirb_http_cgis.txt"
			dirb = "dirb " + str(url) + " " + str(wordlist) + " " + str(outfile2) + " -r"
			subprocess.call(dirb, shell=True)

def gobuster(url):
	print "[!] Starting gobuster scan for " + url
	for wordlist in dirblist:
		if ("big" in wordlist):
			time.sleep(2)
			gobuster = "gobuster -u " + url + " -w " +  str(wordlist) + " -s '200,204,301,302,307,403,500'"
			os.system("gnome-terminal -e 'bash -c \"" + gobuster + "\";bash'")
		elif ("cgis" in wordlist):
			time.sleep(2)
			gobuster = "gobuster -u " + url + " -w " +  str(wordlist) + " -s '200,204,301,302,307,403,500'"
			os.system("gnome-terminal -e 'bash -c \"" + gobuster + "\";bash'")
			
def wfuzz(url):
	print "[!] Starting wfuzz scan for " + url
	for wordlist in wfuzzlist:
		if ("big" in wordlist):
			time.sleep(2)
			wfuzz = "wfuzz --hc 404,403 -c -z file," + wordlist + " " + url + "/FUZZ"
			os.system("gnome-terminal -e 'bash -c \"" + wfuzz + "\";bash'")
		elif ("cgis" in wordlist):
			time.sleep(2)
			wfuzz = "wfuzz --hc 404,403 -c -z file," + wordlist + " " + url + "/FUZZ"
			os.system("gnome-terminal -e 'bash -c \"" + wfuzz + "\";bash'")

def nikto(url):
	print "[!] Launching Nikto for " + url
	cmd = "nikto -Format txt -o /tmp/%s/nikto_http -h %s" % (ip_address, url)
	os.system("gnome-terminal -e 'bash -c \"" + cmd + "\";bash'")
	
def davtest(url):
	print "[!] Launching davtest for " + url
	cmd = "davtest -url %s -cleanup" % (url)
	os.system("gnome-terminal -e 'bash -c \"" + cmd + "\";bash'") 

def main():
	nikto(url)
	time.sleep(2)
	dirb(url)
	time.sleep(2)
	gobuster(url)
	time.sleep(2)
	wfuzz(url)
	time.sleep(2)
	davtest(url)

if __name__=='__main__':
	main()


