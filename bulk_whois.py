#!/usr/bin/python 
try:
	import pythonwhois
	import tldextract
	import csv,datetime,time,sys,os,argparse
	from collections import OrderedDict
except:
	print """
Failed to import the necessary modules to run
Please ensure you have pythonwhois installed.
sudo pip install pythonwhois should do it on debian based systems with pip installed.
"""

def parse_file(filename, output_file):
	input_file = open(filename,'r')
	domains_lookedup = []
	excluded_domains = []
	total_domain_count = 0
	if output_file != 0:
		data = [csv_headers()]
		noutput_file = output_file.split('.',1)[0]+'.csv'
		print """
****************** Writing output to %s ******************
"""%noutput_file
		for domain in input_file.readlines():
			ndomain = tldextract.extract(domain)
			domain = ndomain[1]+'.'+ndomain[2]
			if domain not in domains_lookedup:
				domains_lookedup.append(ndomain)
				total_domain_count += 1
				whois_data = get_whois_data(domain,1)
				if whois_data != 0:
					data.append(whois_data)
				else:
					excluded_domains.append(domain)
				time.sleep(2)
		print """
Attempted to retrieve whois information for %s domains
Successful lookups: %s
Unsuccessful lookups: %s
"""%(str(total_domain_count),str(total_domain_count-len(excluded_domains)),str(len(excluded_domains)))				
		write_to_file(data,noutput_file)
	else:
		for domain in input_file.readlines():
			ndomain = tldextract.extract(domain)
			domain = ndomain[1]+'.'+ndomain[2]
			if domain not in domains_lookedup:
				domains_lookedup.append(domain)
				total_domain_count += 1
				whois_info = get_whois_data(domain,2)
				if whois_info != 0:
					print "\n****************** %s ******************"%domain.strip()
					for key,value in whois_info.items():
						print key+": "+value
				else:
					excluded_domains.append(domain)
				time.sleep(2)
		print """
Attempted to retrieve whois information for %s domains
Successful lookups: %s
Unsuccessful lookups: %s
"""%(str(total_domain_count),str(total_domain_count-len(excluded_domains)),str(len(excluded_domains)))
		print excluded_domains
	 
def get_whois_data(domain,return_type):
	try:
		whois = pythonwhois.get_whois(domain.strip())
	except:
		return 0
	try:
		creation_date = whois['creation_date']
		updated_date = whois['updated_date']
		expiry_date = whois['expiration_date']
		organisation = str(whois['contacts']['registrant']['organization'])
		name = str(whois['contacts']['registrant']['name'])
		email = str(whois['contacts']['registrant']['email'])
		phone = str(whois['contacts']['registrant']['phone'])
		street = str(whois['contacts']['registrant']['street'])
		city = str(whois['contacts']['registrant']['city'])
		postcode = str(whois['contacts']['registrant']['postalcode'])
		country = str(whois['contacts']['registrant']['country'])
	except:
		return 0
	if return_type == 1:
		return (domain.strip(),creation_date[0].strftime('%m/%d/%Y %H:%M'),updated_date[0].strftime('%m/%d/%Y %H:%M'),expiry_date[0].strftime('%m/%d/%Y %H:%M'),organisation,name,email,phone,street,city,postcode,country)
	else:
		data_list = OrderedDict([('Creation Date',creation_date[0].strftime('%m/%d/%Y %H:%M')), 
					 ('Updated Date',updated_date[0].strftime('%m/%d/%Y %H:%M')),
					 ('Expiration Date',expiry_date[0].strftime('%m/%d/%Y %H:%M')),
					 ('Organisation', organisation),
					 ('Name', name),
					 ('Email', email),
					 ('Phone', phone),
					 ('Street', street),
					 ('City', city),
					 ('Postcode', postcode),
					 ('Country',country)
					])
		return data_list
		
def csv_headers():
	data = ('Domain','Creation Date','Updated Date','Expiration Date','Organisation','Name','Email','Phone','Street','City','Postcode','Country')
	return data

def write_to_file(data,output_filename):
	out_headers = open(output_filename,'wb')
	csv_output = csv.writer(out_headers)
	for item in data:
		csv_output.writerow(item)
	out_headers.close()

def main(input_file,output_file):
	parse_file(input_file,output_file)

if __name__ == "__main__":
	parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter, description="""
  ____        _ _     __          ___          _____  _____ 
 |  _ \      | | |    \ \        / / |        |_   _|/ ____|
 | |_) |_   _| | | __  \ \  /\  / /| |__   ___  | | | (___  
 |  _ <| | | | | |/ /   \ \/  \/ / | '_ \ / _ \ | |  \___ \ 
 | |_) | |_| | |   <     \  /\  /  | | | | (_) || |_ ____) |
 |____/ \__,_|_|_|\_\     \/  \/   |_| |_|\___/_____|_____/ 
                                                                                                            
Bulk WhoIS lookup script by Achromatic Security UK
visit https://www.achromatic-security.com/tools for more details.
Thanks.
""")
	parser.add_argument('-i','--input_file',required=True,help='Specify the input file containing a list of domains! (one domain per line)')
	parser.add_argument('-o','--output_file',required=False,help='Specify the output file to write to. If one is not specified output will be displayed to stdout')
   	args = vars(parser.parse_args())	
	if args["output_file"]:
		input_file = args["input_file"]
		output_file = args["output_file"]
		main(input_file,output_file)
	else:
		input_file = args["input_file"]
		main(input_file,0)