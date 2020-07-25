# Dahua Webcrawler

This program tests the world's Dahua security systems for factory passwords. 

Written in Python 3, using Shodan.io.

## Installation

````
pip3 install shodan
````

## Usage
Put your Shodan.io API key in the secrets.py file. 

Then run:
```` python
python3 crawler.py --c <amount of systems to test>
````
After running, the 'vulnerable' hosts are saved in devices.txt which can be used as a template to import into Dahua's SmartPSS, and list.txt which just lists the IP addresses of the hosts.
## Disclaimer
This is made as a proof of concept and using this on systems which aren't yours may be illegal. Only for educational purposes. I am not responsible for misuse of this program.