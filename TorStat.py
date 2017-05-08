#!/usr/bin/env python
import psutil
import urllib2
import json
import socket
from collections import OrderedDict
from colorama import Fore, Style, init
from socket import AF_INET, SOCK_STREAM, SOCK_DGRAM

# Cool Banner
def Banner():
	print '''

	 /$$$$$$$$                   /$$$$$$   /$$                 /$$    
	|__  $$__/                  /$$__  $$ | $$                | $$    
	   | $$  /$$$$$$   /$$$$$$ | $$  \\__//$$$$$$    /$$$$$$  /$$$$$$  
	   | $$ /$$__  $$ /$$__  $$|  $$$$$$|_  $$_/   |____  $$|_  $$_/  
	   | $$| $$  \\ $$| $$  \\__/ \\____  $$ | $$      /$$$$$$$  | $$    
	   | $$| $$  | $$| $$       /$$  \\ $$ | $$ /$$ /$$__  $$  | $$ /$$
	   | $$|  $$$$$$/| $$      |  $$$$$$/ |  $$$$/|  $$$$$$$  |  $$$$/
	   |__/ \\______/ |__/       \\______/   \\___/   \\_______/   \\___/  
		    
		                                  ''' + Style.RESET_ALL + '[' + Fore.YELLOW + '&' + Style.RESET_ALL + '''] Created by Root
						                                                  	                                                                           
		''' 

def TOR_PROC_CHECK():
	isTorRunnin = False
	TOR_INFO = {}
	TOR_PROC = None
	for proc in psutil.process_iter():
		try:
			pinfo = proc.as_dict(attrs=['pid', 'name'])
		except psutil.NoSuchProcess:
			pass
		else:
			if pinfo['name'] == "tor":
				isTorRunnin = True
				TOR_INFO['pid'] = pinfo['pid']
				TOR_INFO['name'] = pinfo['name']
				break

	if isTorRunnin == True:
		print ("[" + Fore.GREEN + Style.BRIGHT + "+" + Style.RESET_ALL + "]" + Fore.GREEN + Style.BRIGHT + " Tor is running." + Style.RESET_ALL)
		TOR_PROC = psutil.Process(int(TOR_INFO['pid']))
		return TOR_PROC
	else:
		print ("[" + Fore.RED + Style.BRIGHT + "-" + Style.RESET_ALL + "]" + Fore.RED + Style.BRIGHT + " Tor is not running." + Style.RESET_ALL)
		exit()

def TABLE_PRETTYPRINT(TOR_PROC):
	AF_INET6 = getattr(socket, 'AF_INET6', object())
	PMAP = {
	    (AF_INET, SOCK_STREAM): 'tcp',
	    (AF_INET6, SOCK_STREAM): 'tcp6',
	    (AF_INET, SOCK_DGRAM): 'udp',
	    (AF_INET6, SOCK_DGRAM): 'udp6',
	}

	print (Fore.BLUE + Style.BRIGHT +"\t=> Process name : %s\n\t=> PID : %s"%(TOR_PROC.name(),TOR_PROC.pid))
	print Style.RESET_ALL
	templete = "%-15s %-25s %-25s %s"
	print (templete % ("Proto", "Local address", "Remote address", "Status"))
	print (templete % ("=====", "=============", "==============", "======"))
	for attr in TOR_PROC.connections(kind='inet'):
		LADDR = "%s:%s"%(attr.laddr)
		RADDR = None
		if attr.raddr:
			RADDR = "%s:%s"%(attr.raddr)
		print (templete % (PMAP[(attr.family, attr.type)], LADDR, RADDR or '-', attr.status))	
	print 	
	

def TOR_CHECK():
	resp = urllib2.urlopen("https://check.torproject.org/api/ip")
	json_data = resp.read()
	data = json.loads(json_data)
	return (data)

def TOR_CHECK_PRNT(data):
	if (data["IsTor"]==True):
		print ("[" + Fore.GREEN + Style.BRIGHT + "+" + Style.RESET_ALL + "]" + Fore.GREEN + Style.BRIGHT + " TorStat's network traffic was routed through tor, onto the next stage...\n" + Style.RESET_ALL)
		return True
	elif (data["IsTor"]==False):
		print ("[" + Fore.YELLOW + Style.BRIGHT + "!" + Style.RESET_ALL + "]" + Fore.YELLOW + Style.BRIGHT +" TorStat cannot perform any more recon on the tor servers because TorStat's network traffic was not routed through tor.\n\t " + Style.RESET_ALL + Fore.WHITE + Style.DIM + "=> try : proxychains python TorStat.py\n" + Style.RESET_ALL)
		return False

def NODE_INFO(IP_ADDR):
	resp = urllib2.urlopen("https://onionoo.torproject.org/details?search=%s"%(IP_ADDR))
	json_data = resp.read()
	data = json.loads(json_data, object_pairs_hook=OrderedDict)
	rp = bp = None
	colors_lst = [Fore.GREEN + Style.BRIGHT, Fore.RED + Style.BRIGHT, Fore.YELLOW + Style.BRIGHT, Fore.WHITE + Style.BRIGHT, Fore.CYAN + Style.BRIGHT]
	for key, value in data.items():
			if key == "version" or key == "bridges":
				continue
			if key == "relays_published":
				rp = value
			if key == "bridges_published":
				bp = value
			if key == "relays":
				for each in value:
					for e_key, e_val in each.items():
						#if lists
						if e_key == "or_addresses":
							print (Fore.GREEN + Style.BRIGHT + e_key.upper() + Fore.WHITE + Style.BRIGHT + " : " + ','.join(e_val))
							continue
						if e_key.lower() == "exit_policy_summary" or e_key.lower() == "exit_policy" or e_key.lower() == "exit_policy_v6_summary": 
							continue
						if str(e_val).startswith("[") and str(e_val).endswith(']'):
							print (Fore.GREEN + Style.BRIGHT + e_key.upper() + Style.RESET_ALL)
							for ef in e_val:
								print Fore.BLUE + Style.BRIGHT + "\t=> "+ ef + Style.RESET_ALL
							continue
						try:	
							print (Fore.GREEN + Style.BRIGHT + e_key.upper().replace('_',' ') + Style.RESET_ALL + " : " + \
						Fore.WHITE + Style.BRIGHT + str(e_val))		
						except: pass
					print
			if (rp!=None and bp!= None):
				print (Fore.GREEN + Style.BRIGHT + "RELAYS PUBLISHED" + Style.RESET_ALL + " : " + Fore.WHITE + Style.BRIGHT + rp)
				print (Fore.GREEN + Style.BRIGHT + "BRIDGES PUBLISHED" + Style.RESET_ALL + " : " + Fore.WHITE + Style.BRIGHT + bp)
				
def Main():
	init()
	Banner()
	TOR_PROC = TOR_PROC_CHECK()
	TABLE_PRETTYPRINT(TOR_PROC)
	data = TOR_CHECK()
	TR_STATUS = TOR_CHECK_PRNT(data)
	if(TR_STATUS == False):
		exit()
	NODE_INFO(data["IP"])
	

if __name__ == '__main__':
	Main()
