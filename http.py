#!/usr/bin/python

import sys, os, subprocess, re, time

if len(sys.argv) != 4:
    print "Usage: ./http.py <protocol> <host> <port>"
    sys.exit(0)

protocol = str(sys.argv[1])
ip_address = str(sys.argv[2])
port = str(sys.argv[3])
url =  "%s://%s:%s" % (protocol, ip_address, port)
path = "/tmp/%s/%s-p%s_" % (ip_address, protocol, port)

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def banner(text, ch='#', length=78):
    spaced_text = ' %s ' % text
    banner = spaced_text.center(length, ch)
    return bcolors.WARNING + banner + bcolors.ENDC

def spawnBash(cmd):
    # Launch a new terminal window for the provided command
    os.system("gnome-terminal -e 'bash -c \"" + cmd + "\";bash'") 

def davtest(url):
    # Davtest launches in the same terminal window
    print banner("davtest")
    cmd = "davtest -cleanup -url " + url
#    print "[*] " + cmd
    subprocess.call(cmd, shell=True)
    print "\n"

def nikto(url):
    # Nikto launches in a separate terminal
    outfile = path + "nikto.txt"
    cmd = "nikto -Format txt -output " + outfile + " -host " + url + " | tee " + outfile + ".teed"
#    print "[*] " + cmd
    spawnBash(cmd)

def dirb(url):
    # Dirb and gobuster launch in the same terminal window
    print banner("dirb scan (common)")
    outfile = path + "dirb_common.txt"
    cmd = "dirb " + str(url) + " /usr/share/dirb/wordlists/common.txt -r -o " + outfile
    print "[*] " + cmd
    subprocess.call(cmd, shell=True)
    
    print ""
    
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
    
    print ""
	
    print banner("gobuster scan (cgis)")
    outfile = path + "gobuster_cgis.txt"
    cmd = "gobuster -u " + url + " -w /usr/share/seclists/Discovery/Web_Content/cgis.txt | tee " + outfile
    print "[*] " + cmd
    subprocess.call(cmd, shell=True)
    
    print "\n\n"
			
def wfuzz(url):
    wfuzzlist = ["/usr/share/wfuzz/wordlist/general/common.txt", "/usr/share/wfuzz/wordlist/vulns/cgis.txt"]
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
    print bcolors.WARNING + "#"*78 + bcolors.ENDC
    print banner("HTTP Testing: " + url)
    print bcolors.WARNING + "#"*78 + bcolors.ENDC
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


