#!/usr/bin/env python3
#
# ESEDHOUND
#
# Author:
#   Processus (@ProcessusT)
#
#
# Based on https://github.com/libyal/libesedb
# and the FUCKING OLD PYTHON2 TOOL https://github.com/csababarta/ntdsxtract

import sys
import os
import argparse
import logging
from lib.esedbexport import ESEDBExport
from time import sleep
from rich.console import Console
from ntds.version import *
from ntds.dsdatabase import *
from ntds.dsrecord import *
from ntds.dslink import *
from ntds.dstime import *
from ntds.dsobjects import *
from lib.dump import *
from lib.fs import *
from lib.hashoutput import *
from lib.csvoutput import *

# custom
from ntds.sd_table import *



def test_esedbexport():
	try:
		if os.path.isfile('/usr/local/bin/esedbexport'):
			return 0
		else:
			print("[!] The esedbexport tool is not installed !")
			console = Console()
			workdir=os.getcwd()
			with console.status("[bold green][+] Installing esedbexport...") as status:
				os.system("wget https://github.com/Processus-Thief/libesedb/releases/download/release/libesedb-experimental-20230318.tar.gz")
				os.system("tar xf libesedb-experimental-20230318.tar.gz")
				os.system("sudo apt update && sudo apt-get install autoconf automake autopoint libtool pkg-config -y")
				os.chdir("./libesedb-20230318")
				os.system("./configure && make && make install && ldconfig")
				os.chdir("..")
				if os.path.isfile('/usr/local/bin/esedbexport'):
					return 0
				else:
					print("[!] Installation failed. Abort.")
					raise
	except Exception as e:
		print("Failed to create instance of ESEDBExport : "+str(e))
		raise



def export_tables(ntds):
	try:
		console = Console()
		workdir=os.getcwd()
		with console.status("[bold green][+] Extracting ESE databases (Stage 0)...") as status:
			esedbexport = ESEDBExport(ntds=ntds, workdir=workdir)
			datatable = esedbexport.ExportTable(ntds=ntds,table="datatable")
			link_table = esedbexport.ExportTable(ntds=ntds,table="link_table")
			sd_table = esedbexport.ExportTable(ntds=ntds,table="sd_table")
		print("[+] Extracting ESE databases (Stage 0)...")
		with console.status("[bold green][+] Extracting datatable...") as status:
			datatable.run()
		print("[+] Extracting datatable...")
		with console.status("[bold green][+] Extracting link_table...") as status:
			link_table.run()
		print("[+] Extracting link_table...")
		with console.status("[bold green][+] Extracting sd_table...") as status:
			sd_table.run()
		print("[+] Extracting sd_table...")
	except Exception as e:
		os.system("rm -f ./*.map && rm -rf ./datatable.export && rm -rf ./link_table.export && rm -rf ./sd_table")
		print("Failed to create instance of ESEDBExport : "+str(e))
		raise



def read_sd_table():
	try:
		console = Console()
		workdir=os.getcwd()
		with console.status("[bold green][+] Initializing engine for sd_table...") as status:
			for filename in os.listdir("./sd_table.export"):
				f = os.path.join("./sd_table.export", filename)
				if not os.path.isfile(f):
					print("\n[!] ERROR : sd_table file not generated.")
					raise
		print("[+] Initializing engine for sd_table...")
		sd = dsInitSdTable(f, workdir)

		return sd
	except Exception as e:
		os.system("rm -f ./*.map && rm -rf ./datatable.export && rm -rf ./link_table.export && rm -rf ./sd_table")
		print("Failed to create instance of ESEDBExport : "+str(e))
		raise



def read_datatable():
	try:
		console = Console()
		workdir=os.getcwd()
		with console.status("[bold green][+] Initializing engine for datatable...") as status:
			for filename in os.listdir("./datatable.export"):
				f = os.path.join("./datatable.export", filename)
				if not os.path.isfile(f):
					print("\n[!] ERROR : datatable file not generated.")
					raise
		print("[+] Initializing engine for datatable...")
		db = dsInitDatabase(f, workdir)

		with console.status("[bold green][+] Initializing engine for link_table...") as status:
			for filename in os.listdir("./link_table.export"):
				f = os.path.join("./link_table.export", filename)
				if os.path.isfile(f):
					dl = dsInitLinks(f, workdir)
				else:
					print("\n[!] ERROR : linktable file not generated.")
					raise
		print("[+] Initializing engine for link_table...")
		return db, dl
	except Exception as e:
		os.system("rm -f ./*.map && rm -rf ./datatable.export && rm -rf ./link_table.export && rm -rf ./sd_table")
		print("Failed to create instance of ESEDBExport : "+str(e))
		raise	




def print_users(db):
	try:
		console = Console()
		with console.status("[bold green][+] Getting Person object type...") as status:
			utype = dsGetTypeIdByTypeName(db, "Person")
		print("[+] Getting Person object type...")
		print("\n[+] List of users:")
		print("==============")
		for recordid in dsMapLineIdByRecordId:
			if int(dsGetRecordType(db, recordid)) == utype:
				user = None
				try:
					user = dsUser(db, recordid)
				except:
					print("[!] Unable to instantiate user object (record id: %d)" % recordid)
					raise

				print("\n\nRecord ID:\t%d" % user.RecordId)
				print("User name:\t%s" % user.Name)
				print("User principal name:\t%s" % user.PrincipalName)
				print("SAM Account name:\t%s" % user.SAMAccountName)
				print("SAM Account type:\t%s" % user.getSAMAccountType())
				print("GUID:\t%s" % str(user.GUID))
				print("SID:\t%s" % str(user.SID))
				print("When created:\t%s" % dsGetDSTimeStampStr(user.WhenCreated))
				print("When changed:\t%s" % dsGetDSTimeStampStr(user.WhenChanged))
				print("Account expires:\t%s" % dsGetDSTimeStampStr(user.AccountExpires))
				print("Password last set:\t%s" % dsGetDSTimeStampStr(user.PasswordLastSet))
				print("Last logon:\t%s" % dsGetDSTimeStampStr(user.LastLogon))
				print("Last logon timestamp:\t%s" % dsGetDSTimeStampStr(user.LastLogonTimeStamp))
				print("Bad password time:\t%s" % dsGetDSTimeStampStr(user.BadPwdTime))
				print("Logon count:\t%d" % user.LogonCount)
				print("Bad password count:\t%d" % user.BadPwdCount)
				gtype = dsGetTypeIdByTypeName(db, "Group")
				groups=[]
				ugroups=[]
				if user.PrimaryGroupID != -1:
					print("Member of:")
					for recordid in dsMapLineIdByRecordId:
						if int(dsGetRecordType(db, recordid)) == gtype:
							groups.append(dsGroup(db, recordid))
					grouplist = user.getMemberOf()
					for g in groups:
						if g.SID.RID == user.PrimaryGroupID:
							print("\t%s" % g.Name)
						else:
							for g_user in grouplist:
								if g.RecordId == g_user[0]:
									print("\t%s" % g.Name)
				print("User Account Control:")
				for uac in user.getUserAccountControl():
					print("\t%s" % uac)
				i=0
				str_anc = ""
				for ancestor in user.getAncestors(db):
					if i<1:
						i=1
					else:
						str_anc = str_anc + "->"
					str_anc = str_anc + ancestor.Name 
				print("Ancestors: " + str(str_anc))		
	except Exception as e:
		os.system("rm -f ./*.map && rm -rf ./datatable.export && rm -rf ./link_table.export && rm -rf ./sd_table")
		print("Failed to create instance of ESEDBExport : "+str(e))
		raise




def print_computers(db):
	try:	
		print("\n[+] List of computers:")
		print("==============")
		for recordid in dsMapRecordIdByTypeId[dsGetTypeIdByTypeName(db, "Computer")]:
		    computer = None
		    try:
		        computer = dsComputer(db, recordid)
		    except KeyboardInterrupt:
		        raise KeyboardInterrupt
		    except:
		        print("[!] Unable to instantiate user object (record id: %d)" % recordid)
		        continue
		    print("\n\nRecord ID:\t%d" % computer.RecordId)
		    print("Computer name:\t%s" % computer.Name)
		    print("Computer DNS Hostname:\t%s" % computer.DNSHostName)
		    print("GUID:\t%s" % str(computer.GUID))
		    print("SID:\t%s" % str(computer.SID))
		    print("Computer OS Name:\t%s" % computer.OSName)
		    print("Computer OS Version:\t%s" % computer.OSVersion)
		    print("When created:\t%s" % dsGetDSTimeStampStr(computer.WhenCreated))
		    print("When changed:\t%s" % dsGetDSTimeStampStr(computer.WhenChanged))
	except Exception as e:
		os.system("rm -f ./*.map && rm -rf ./datatable.export && rm -rf ./link_table.export && rm -rf ./sd_table")
		print("Failed to create instance of ESEDBExport : "+str(e))
		raise




def print_groups(db):
	try:
		console = Console()
		with console.status("[bold green][+] Getting Group object type...") as status:
			gtype = dsGetTypeIdByTypeName(db, "Group")
		print("[+] Getting Group object type...")	
		print("\n[+] List of groups:")
		print("==============")
		for recordid in dsMapLineIdByRecordId:
		    if int(dsGetRecordType(db, recordid)) == gtype:
		        try:
		            group = dsGroup(db, recordid)
		        except:
		            print("\n[!] Unable to instantiate group object (record id: %d)" % recordid)
		            continue		  
		        print("\n\nRecord ID:\t%d" % group.RecordId)
		        print("Group Name:\t%s" % group.Name)
		        print("GUID:\t%s" % str(group.GUID))
		        print("SID:\t%s" % str(group.SID))
		        print("When created:\t%s" % dsGetDSTimeStampStr(group.WhenCreated))
		        print("When changed:\t%s" % dsGetDSTimeStampStr(group.WhenChanged))
	except Exception as e:
		os.system("rm -f ./*.map && rm -rf ./datatable.export && rm -rf ./link_table.export && rm -rf ./sd_table")
		print("Failed to create instance of ESEDBExport : "+str(e))
		raise


	



def main():
	print("***************************\n\tESEDHOUND\n***************************\n")
	parser = argparse.ArgumentParser(add_help = True, description = "ESEDHOUND is a python script that extract datatable from the ntds.dit file to retrieve users, computers and groups")
	parser.add_argument('-v', action="store_true", help='verbose mode')
	file = parser.add_argument_group('File')
	file.add_argument('-ntds', action='store', required=True, help='ntds file location')
	if len(sys.argv)==1:
		parser.print_help()
		sys.exit(1)
	options = parser.parse_args()
	if options.ntds is None:
		print("No ntds file")
		sys.exit(1)
	else:
		ntds = options.ntds
	debug = options.v

	export_tables(ntds)
	db, dl = read_datatable()
	
	print_users(db)

	#print_computers(db)

	#print_groups(db)
	
	# For further uses : extract ACLs from sd table
	#read_sd_table()


	os.system("rm -f ./*.map && rm -rf ./datatable.export && rm -rf ./link_table.export && rm -rf ./sd_table")






if __name__ == "__main__":
	try:
		test_esedbexport()
		main()
	except KeyboardInterrupt:
		os.system("rm -f ./*.map && rm -rf ./datatable.export && rm -rf ./link_table.export && rm -rf ./sd_table.export")
		raise
