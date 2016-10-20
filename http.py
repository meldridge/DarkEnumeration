#!/usr/bin/python

import sys, os, subprocess, re, time

if len(sys.argv) != 2:
    print "Usage: ./http.py <target>"
    sys.exit(0)

ip_address = str(sys.argv[1])
url =  "http://" + ip_address
path = "/tmp/" + ip_address + "/http_"

wfuzzlist = ["/usr/share/wfuzz/wordlist/general/common.txt", "/usr/share/wfuzz/wordlist/vulns/cgis.txt"]

def banner(text, ch='=', length=78):
    spaced_text = ' %s ' % text
    banner = spaced_text.center(length, ch)
    return banner

def spawnBash(cmd):
    # Launch a new terminal window for the provided command
    os.system("gnome-terminal -e 'bash -c \"" + cmd + "\";bash'") 

def davtest(url):
    # Davtest launches in the same terminal window
    print banner("davtest")
    cmd = "davtest -cleanup -url " + url
#    print "[*] " + cmd
    subprocess.call(cmd, shell=True)
    print "\n\n"

def nikto(url):
    # Nikto launches in a separate terminal
    outfile = path + "nikto.txt"
    cmd = "nikto -Format txt -output " + outfile + " -host " + ip_address + " | tee " + outfile + ".teed"
#    print "[*] " + cmd
    spawnBash(cmd)

def dirb(url):
    # Dirb and gobuster launch in the same terminal window
    print banner("dirb scan (common)")
    outfile = path + "dirb_common.txt"
    cmd = "dirb " + str(url) + " /usr/share/dirb/wordlists/common.txt -r -o " + outfile
    print "[*] " + cmd
    subprocess.call(cmd, shell=True)
    
    print banner("dirb scan (cgis)")
    outfile = path + "dirb_cgis.txt"
    cmd = "dirb " + str(url) + " /usr/share/dirb/wordlists/vulns/cgis.txt -r -o " + outfile
    print "[*] " + cmd
    subprocess.call(cmd, shell=True)
    
    print "\n\n"

def gobuster(url):
    # Dirb and gobuster launch in the same terminal window
    print banner("gobuster scan (common)")
    outfile = path + "gobuster_common.txt"
    cmd = "gobuster -u " + url + " -w /usr/share/seclists/Discovery/Web_Content/common.txt | tee " + outfile
    print "[*] " + cmd
    subprocess.call(cmd, shell=True)
	
    print banner("gobuster scan (cgis)")
    outfile = path + "gobuster_cgis.txt"
    cmd = "gobuster -u " + url + " -w /usr/share/seclists/Discovery/Web_Content/cgis.txt | tee " + outfile
    print "[*] " + cmd
    subprocess.call(cmd, shell=True)
    
    print "\n\n"
			
def wfuzz(url):
    print "[*] Starting wfuzz scan for " + url
    for wordlist in wfuzzlist:
        if ("big" in wordlist):
            time.sleep(2)
            wfuzz = "wfuzz --hc 404,403 -c -z file," + wordlist + " " + url + "/FUZZ"
            os.system("gnome-terminal -e 'bash -c \"" + wfuzz + "\";bash'")
        elif ("cgis" in wordlist):
            time.sleep(2)
            wfuzz = "wfuzz --hc 404,403 -c -z file," + wordlist + " " + url + "/FUZZ"
            os.system("gnome-terminal -e 'bash -c \"" + wfuzz + "\";bash'")

def main():
    print banner("HTTP Testing")
    print banner("" + url)
    print "\n"
    
    # Nikto launches in a new bash window
    nikto(url)
    
    # Remaining tests
    davtest(url)
    dirb(url)
    gobuster(url)
#    wfuzz(url)
#    time.sleep(2)


if __name__=='__main__':
	main()


