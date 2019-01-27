from * import nmap
nm = nmap.PortScanner()
nm.scan('127.0.0.1', '22-443') # Test Scan

# Default Commands | How To Use Use Code By SkyHax0

nm.command_line()
# >> nmap -oX - -p 22-443 -sV 127.0.0.1
# > Default Scan Info
nm.scaninfo()
# >> {"tcp" : {"services": "22-443", "method": 'connect'}}
nm.all_host()
# >> Default : 127.0.0.1 | output : ['127.0.0.1']
# Can Usable NMAP PORT Scanners
nm['127.0.0.1'].hostname() # Maybe Later you Can Change Ip To all_host exam : nm.all_host.hostname()
# >> "localhost"
nm['127.0.0.1'].state()
# If 80 Port (Default Apache etc. Ports...) Open Shows on screen | >> 'up'
nm['127.0.0.1'].all_protocols()
# >> ['tcp']
nm['127.0.0.1']['tcp'].keys()
# Shows Open Ports exam : | >> [80, 25, 443, 22, 111]
nm['127.0.0.1'].has_tcp(22)
# >> True | If State Is Open Shows True - If State Is Closed Shows False
nm['127.0.0.1'].has_tcp(23)
# >> False | ^^
nm['127.0.0.1']['tcp'][22]
# >> {'state': 'open', 'reason': 'syn-ack', 'name': 'ssh'} | Shows Current States Informations
nm['127.0.0.1'].tcp(22)
# >> {'state': 'open', 'reason': 'syn-ack', 'name': 'ssh'} | ^^
nm['127.0.0.1']['tcp'][22]['state']
# >> 'open' | open or close

# Examle Codes 
 for host in nm.all_hosts():
     print('----------------------------------------------------')
     print('Host : %s (%s)' % (host, nm[host].hostname()))
     print('State : %s' % nm[host].state())
     for proto in nm[host].all_protocols():
         print('----------')
         print('Protocol : %s' % proto)
 
         lport = nm[host][proto].keys()
         lport.sort()
         for port in lport:
             print ('Port : %s\tstate : %s' % (port, nm[host][proto][port]['state']))

print(nm.csv())

nm.scan(hosts='192.168.1.0/24', arguments='-n -sP -PE -PA21,23,80,3389')
hosts_list = [(x, nm[x]['status']['state']) for x in nm.all_hosts()]
 for host, status in hosts_list:
     print('{0}:{1}'.host)


nma = nmap.PortScannerAsync()
 def callback_result(host, scan_result):
     print '------------------'
     print host, scan_result
 
nma.scan(hosts='192.168.1.0/30', arguments='-sP', callback=callback_result)
 while nma.still_scanning():
     print("Waiting >>>")
     nma.wait(2)

nm = nmap.PortScannerYield()
 for progressive_result in nm.scan('127.0.0.1/24', '22-25'):
	print(progressive\_result)