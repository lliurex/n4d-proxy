# npackage example  https://svn.lliurex.net/pandora/n4d-ldap/trunk
# jinja2 http://jinja.pocoo.org/docs/templates

from jinja2 import Environment
from jinja2.loaders import FileSystemLoader
from jinja2 import Template
import tempfile
import shutil
import os
import subprocess
import tarfile
import time

class N4dProxy:

	def __init__(self):
		#Load template file
		self.tpl_env = Environment(loader=FileSystemLoader('/usr/share/n4d/templates/squid'))
		self.proxy_file_list=["/etc/squid/squid.conf","/var/www/proxy.pac","/var/lib/dnsmasq/config/cname-proxy"]
		self.proxy_dirs=["/etc/squid/lliurex/"]
		
	#def init
	
	def startup(self,options):
		# executed when launching n4d
		pass
		
	#def startup

	def apt(self):
		# executed after apt operations
		pass
		
	#def apt
	
	# service test and backup functions #
	
	def test(self):

		pass
		
	#def test

	def get_time(self):
		
		return get_backup_name("ProxyManager")
		
	#def get_time
	
	
	def backup(self,dir="/backup"):
		
		try:
		
			file_path=dir+"/"+self.get_time()
		
			tar=tarfile.open(file_path,"w:gz")
			
			for f in self.proxy_file_list:
				
				tar.add(f)
			
			for d in self.proxy_dirs:
				if os.path.exists(d):
					tar.add(d)
			
			
			tar.close()
			
			return [True,file_path]
			
		except Exception as e:
			return [False,str(e)]
		
	#def test
	
	def restore(self,file_path=None):

		try:

			if file_path==None:
				for f in sorted(os.listdir("/backup"),reverse=True):
					if "ProxyManager" in f:
						file_path="/backup/"+f
						break			
			
			if file_path==None:
				
				return [False,"Backup file not found"]

			if os.path.exists(file_path):
				
				tmp_dir=tempfile.mkdtemp()
				tar=tarfile.open(file_path)
				tar.extractall(tmp_dir)
				tar.close()
				
				#FIX squid dir from backups <= 15.05
				version=objects["ServerBackupManager"].restoring_version
				majorBackupVersion=int(version[0:version.find('.')])
				for f in self.proxy_file_list:
					auxFile=f
					if auxFile == "/etc/squid/squid.conf" :
						if majorBackupVersion<=15:
							auxFile='/etc/squid3/squid.conf'
					
#					tmp_path=tmp_dir+f
					tmp_path=tmp_dir+auxFile
					shutil.copy(tmp_path,f)
					
				for d in self.proxy_dirs:
					auxDir=d
					if auxDir == "/etc/squid/lliurex/" :
						if majorBackupVersion<=15:
							auxDir='/etc/squid3/lliurex/'
						
#					tmp_path=tmp_dir+d
					tmp_path=tmp_dir+auxDir
					if os.path.exists(tmp_path):
						cmd="cp -r " + tmp_path +"/* "  + d
						if not os.path.exists(d):
							os.makedirs(d)
						os.system(cmd)
				
				try:
					if majorBackupVersion<=15 :

#					if objects["ServerBackupManager"].restoring_version=="14.06":
							
						print("[ProxyManager] Fixing squid.conf ...")
						
						f=open("/etc/squid/squid.conf")
						lines=f.readlines()
						f.close()
						
						f=open("/tmp/squid.conf","w")
						for line in lines:
							if "acl manager proto cache_object" not in line:
								#FIX squid dir from backups <= 15.05
								line=line.replace ("squid3","squid")
								if "dns_nameservers" in line:
									line="dns_nameservers 127.0.0.1\n"
								
								f.write(line)
						
						f.close()
						
						shutil.copy("/tmp/squid.conf","/etc/squid/squid.conf")
					
				except Exception as llx14_ex:
					print llx14_ex
					
				os.system("service squid restart")
						
				return [True,""]
				
			else:
				return [False,"Backup file not found"]
				
		except Exception as e:
			print e
			return [False,str(e)]
		
	#def test
	
	def calc_longmask(self,bitmask):
		binario = "1"*bitmask + "0"*(32-bitmask)
		longmask = longmask = str(int(binario[0:8],2)) + "." + str(int(binario[8:16],2)) + "." + str(int(binario[16:24],2)) + "." + str(int(binario[24:32],2))
		return longmask
	#def calc_longmask
	
	
	def load_exports(self):
		#Get template
		template = self.tpl_env.get_template("squid.conf")
		template_dst_domains = self.tpl_env.get_template("allow-dst-domains.conf")
		template_dst_networks = self.tpl_env.get_template("allow-dst-networks.conf")
		template_src_networks = self.tpl_env.get_template("allow-src-networks.conf")
		template_ssl_ports = self.tpl_env.get_template("allow-SSL-ports.conf")
		template_deny_dst_domain = self.tpl_env.get_template("deny-dst-domains.conf")
		template_deny_dst_domain_expr = self.tpl_env.get_template("deny-dst-domains-expr.conf")
		template_deny_dst_networks = self.tpl_env.get_template("deny-dst-networks.conf")
		template_cache_networks = self.tpl_env.get_template("no_cache_networks.conf")
		template_proxy_pac = self.tpl_env.get_template("proxy.pac")
		template_cname = self.tpl_env.get_template("cname")
		list_variables = {}
		
		###########################
		#Getting VARS
		###########################

		#Obtains SRV_IP
		list_variables['SRV_IP'] = objects['VariablesManager'].get_variable('SRV_IP')
		#If variable INTERNAL_IP is not defined returns an error
		if  list_variables['SRV_IP'] == None:
			return {'status':False,'msg':'Variable SRV_IP not defined'}
				
		#Obtains INTERNAL_MASK 
		list_variables['INTERNAL_MASK'] = objects['VariablesManager'].get_variable('INTERNAL_MASK')
		#If INTERNAL_MASK is not defined returns an error
		if  list_variables['INTERNAL_MASK'] == None:
			return {'status':False,'msg':'Variable INTERNAL_MASK not defined'}
		
		#Calculate INTERNAL_LONGMASK
		list_variables['INTERNAL_LONGMASK'] = self.calc_longmask(list_variables['INTERNAL_MASK'])
		
		
		#Obtains INTERNAL_NETWORK
		list_variables['INTERNAL_NETWORK'] = objects['VariablesManager'].get_variable('INTERNAL_NETWORK')
		#If INTERNAL_NETWORK is not defined returns an error
		if  list_variables['INTERNAL_NETWORK'] == None:
			return {'status':False,'msg':'Variable INTERNAL_NETWORK not defined'}
		
		#Obtains INTERNAL_DOMAIN
		list_variables['INTERNAL_DOMAIN'] = objects['VariablesManager'].get_variable('INTERNAL_DOMAIN')
		#If INTERNAL_DOMAIN is not defined returns an error
		if  list_variables['INTERNAL_DOMAIN'] == None:
			return {'status':False,'msg':'Variable INTERNAL_DOMAIN not defined'}
			
		#Obtains HOSTNAME
		list_variables['HOSTNAME'] = objects['VariablesManager'].get_variable('HOSTNAME')
		#If variable SRV_IP is not defined returns an error
		if  list_variables['HOSTNAME'] == None:
			return {'status':False,'msg':'Variable HOSTNAME not defined'}
			
		###########################
		#Setting VARS
		###########################
		
		#Set PROXY_HOST
		list_variables['PROXY_HOST'] = objects['VariablesManager'].get_variable('PROXY_HOST')
		#If variable PROXY_HOST is not defined calculate it with args values
		if  list_variables['PROXY_HOST'] == None:
			status,list_variables['PROXY_HOST'] = objects['VariablesManager'].init_variable('PROXY_HOST',{'HOST':"proxy"})
				
		#Set PROXY_HTTP_PORT
		list_variables['PROXY_HTTP_PORT'] = objects['VariablesManager'].get_variable('PROXY_HTTP_PORT')
		#If variable PROXY_HTTP_PORT is not defined calculate it with args values
		if  list_variables['PROXY_HTTP_PORT'] == None:
			status,list_variables['PROXY_HTTP_PORT'] = objects['VariablesManager'].init_variable('PROXY_HTTP_PORT',{'PORT':3128})
		
		#Set PROXY_ENABLED
		list_variables['PROXY_ENABLED'] = objects['VariablesManager'].get_variable('PROXY_ENABLED')
		#If variable PROXY_ENABLED is not defined calculate it with args values
		if  list_variables['PROXY_ENABLED'] == None:
			status,list_variables['PROXY_ENABLED'] = objects['VariablesManager'].init_variable('PROXY_ENABLED',{'ENABLED':True})
		
		#Set PROXY_MAX_FILE_SIZE
		list_variables['PROXY_MAX_FILE_SIZE'] = objects['VariablesManager'].get_variable('PROXY_MAX_FILE_SIZE')
		#If variable PROXY_ENABLED is not defined calculate it with args values
		if  list_variables['PROXY_MAX_FILE_SIZE'] == None:
			status,list_variables['PROXY_MAX_FILE_SIZE'] = objects['VariablesManager'].init_variable('PROXY_MAX_FILE_SIZE',{'FILE_SIZE':204800})
		
		#Encode vars to UTF-8
		string_template = template.render(list_variables).encode('UTF-8')
		#Open template file
		fd, tmpfilepath = tempfile.mkstemp()
		new_export_file = open(tmpfilepath,'w')
		new_export_file.write(string_template)
		new_export_file.close()
		os.close(fd)
		#Write template values
		n4d_mv(tmpfilepath,'/etc/squid/squid.conf',True,'root','root','0644',False )
		
		#Encode vars to UTF-8
		string_template = template_dst_domains.render(list_variables).encode('UTF-8')
		#Open template file
		fd, tmpfilepath = tempfile.mkstemp()
		new_export_file = open(tmpfilepath,'w')
		new_export_file.write(string_template)
		new_export_file.close()
		os.close(fd)
		#Write template values
		n4d_mv(tmpfilepath,'/etc/squid/lliurex/allow-dst-domains.conf',True,'root','root','0644',True )
		
		#Encode vars to UTF-8
		string_template = template_dst_networks.render(list_variables).encode('UTF-8')
		#Open template file
		fd, tmpfilepath = tempfile.mkstemp()
		new_export_file = open(tmpfilepath,'w')
		new_export_file.write(string_template)
		new_export_file.close()
		os.close(fd)
		#Write template values
		n4d_mv(tmpfilepath,'/etc/squid/lliurex/allow-dst-networks.conf',True,'root','root','0644',True )
		
		#Encode vars to UTF-8
		string_template = template_src_networks.render(list_variables).encode('UTF-8')
		#Open template file
		fd, tmpfilepath = tempfile.mkstemp()
		new_export_file = open(tmpfilepath,'w')
		new_export_file.write(string_template)
		new_export_file.close()
		os.close(fd)
		#Write template values
		n4d_mv(tmpfilepath,'/etc/squid/lliurex/allow-src-networks.conf',True,'root','root','0644',True )
		
		#Encode vars to UTF-8
		string_template = template_ssl_ports.render(list_variables).encode('UTF-8')
		#Open template file
		fd, tmpfilepath = tempfile.mkstemp()
		new_export_file = open(tmpfilepath,'w')
		new_export_file.write(string_template)
		new_export_file.close()
		os.close(fd)
		#Write template values
		n4d_mv(tmpfilepath,'/etc/squid/lliurex/allow-SSL-ports.conf',True,'root','root','0644',True )
		
		#Encode vars to UTF-8
		string_template = template_cache_networks.render(list_variables).encode('UTF-8')
		#Open template file
		fd, tmpfilepath = tempfile.mkstemp()
		new_export_file = open(tmpfilepath,'w')
		new_export_file.write(string_template)
		new_export_file.close()
		os.close(fd)
		#Write template values
		n4d_mv(tmpfilepath,'/etc/squid/lliurex/no_cache_networks.conf',True,'root','root','0644',True )
		
		#Encode vars to UTF-8
		string_template = template_proxy_pac.render(list_variables).encode('UTF-8')
		#Open template file
		fd, tmpfilepath = tempfile.mkstemp()
		new_export_file = open(tmpfilepath,'w')
		new_export_file.write(string_template)
		new_export_file.close()
		os.close(fd)
		#Write template values
		n4d_mv(tmpfilepath,'/var/www/proxy.pac',True,'root','root','0644',True )
		
		#Encode vars to UTF-8
		string_template = template_cname.render(list_variables).encode('UTF-8')
		#Open template file
		fd, tmpfilepath = tempfile.mkstemp()
		new_export_file = open(tmpfilepath,'w')
		new_export_file.write(string_template)
		new_export_file.close()
		os.close(fd)
		#Write template values
		n4d_mv(tmpfilepath,'/var/lib/dnsmasq/config/cname-proxy',True,'root','root','0644',True )
		
		#deny-dst-domains
		string_template = template_deny_dst_domain.render(list_variables).encode('UTF-8')
		#Open template file
		fd, tmpfilepath = tempfile.mkstemp()
		new_export_file = open(tmpfilepath,'w')
		new_export_file.write(string_template)
		new_export_file.close()
		os.close(fd)
		#Write template values
		n4d_mv(tmpfilepath,'/etc/squid/lliurex/deny-dst-domains.conf',True,'root','root','0644',True )
		
		#deny-dst-domains-expr
		string_template = template_deny_dst_domain_expr.render(list_variables).encode('UTF-8')
		#Open template file
		fd, tmpfilepath = tempfile.mkstemp()
		new_export_file = open(tmpfilepath,'w')
		new_export_file.write(string_template)
		new_export_file.close()
		os.close(fd)
		#Write template values
		n4d_mv(tmpfilepath,'/etc/squid/lliurex/deny-dst-domains-expr.conf',True,'root','root','0644',True )
		
		#deny-dst-networks
		string_template = template_deny_dst_networks .render(list_variables).encode('UTF-8')
		#Open template file
		fd, tmpfilepath = tempfile.mkstemp()
		new_export_file = open(tmpfilepath,'w')
		new_export_file.write(string_template)
		new_export_file.close()
		os.close(fd)
		#Write template values
		n4d_mv(tmpfilepath,'/etc/squid/lliurex/deny-dst-networks.conf',True,'root','root','0644',True )
		
		
		return {'status':True,'msg':'Exports written'}
	#def load_exports

	def reboot_squid(self):
		#Restart nfs service
		subprocess.Popen(['/etc/init.d/squid','restart'],stdout=subprocess.PIPE).communicate()
		return {'status':True,'msg':'SQUID3 rebooted'}
	#def reboot_squid

	# ######################### #
	
#class N4dProxy 
