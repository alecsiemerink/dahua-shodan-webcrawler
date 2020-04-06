import shodan
from secrets import *

api = shodan.Shodan(SHODAN_API_KEY)

# YET TO DECIDE WHICH FUNCTION TO USE
def getAddresses2():
    limit = 15
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


def getAddresses():
    try:
        # Search Shodan
        results = api.search('Dahua country:NL')
        # Show the results
        ipList = []
        print('Results found: {}'.format(results['total']))
        for result in results['matches']:
            ip = str(result['ip_str'])
            print(ip)
            ipList.append(ip)
        return ipList
    except shodan.APIError, e:
        print('Error: {}'.format(e))
    return ipList


print getAddresses2()
