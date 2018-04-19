#!/usr/bin/env python
# A very fast, multi-threaded s3 bucket enumeration script based on a dictionary file
# Written by: unitato
# 
# Configuration: access_key,aws_secret_key,threads
#
# Usage: s3enum.py -d amazon.com
#


from boto.s3.connection import S3Connection
from boto.s3.connection import OrdinaryCallingFormat
import requests
from multiprocessing.dummy import Pool as ThreadPool
import boto
from colorama import init
from colorama import Fore
from colorama import Back
from colorama import Style
from time import sleep
import re
import argparse
import sys
import os
import time


access_key = 'xxxxxxx'
aws_secret_key = 'xxxxxxxxxxx'
threads = 50

start_time = time.time()

requests.packages.urllib3.disable_warnings()

parser = argparse.ArgumentParser(description='This script tries to brutefoce s3 bucket names based on a domain name.')
parser.add_argument('-d','--domain', help='Please specify domain to audit', default="_check_string_for_empty_")
parser.add_argument('--version', action='version', version='%(prog)s 3.1')

#parser.add_argument('-b','--bar', help='Description for bar argument', required=True)
args = vars(parser.parse_args())
print(args)


pool = ThreadPool(threads)

print("Number of threads: %s" % threads )

if args['domain'] == '_check_string_for_empty_':
        print('I can tell that no argument was given and I can deal with that here.')
        domain = input("Domain to check:")
        domain = domain.strip()
else:
        domain = args['domain'].strip()



headers = {
    'User-Agent': 'Mozilla/5.0 (compatible; MSIE 8.5; Windows NT 6.1; NET CLR 3.3.69573; WOW64; en-US)'
}

def get_page(host):
        try:
                r = requests.get(host, verify=False, headers=headers) #, proxies=proxies
                return (r)
        except requests.ConnectionError as e:
                print("failed to connect to %s - %s" % (host,e) )


##check for proxy
ip_checker_url = 'https://api.ipify.org'
myip = requests.get(ip_checker_url).text
print("Your External IP: %s" % myip)

#access_key = input("Access Key: ")
#aws_secret_key = input("Secret Key: ")
print("Enumerating S3 buckets")
#create enumerated directry
test_s3_buckets = []
root = []
root.append(domain.replace(".", ""))
root.append(domain.replace(".com", ""))
root.append(domain.replace(".io", ""))
root.append(domain.replace(".ca", ""))
root.append(domain.replace(".net", ""))
root.append(domain.replace(".org", ""))
root = list(set(root))

print("Adding doman variations... %s" % root)

base_dir = os.path.dirname(os.path.realpath(sys.argv[0]))

for prefix in open("%s/bucket_suffixes.txt" % base_dir,'r'):
        prefix = re.sub(r"\W", "", prefix)
        for r in root:
                bucket = "%s%s" % (r,prefix)
                test_s3_buckets.append(bucket)
                bucket = "%s%s" % (prefix,r)
                test_s3_buckets.append(bucket)

                if(prefix):
                    bucket = "%s-%s" % (r,prefix)
                    test_s3_buckets.append(bucket)
                    bucket = "%s_%s" % (r,prefix)
                    test_s3_buckets.append(bucket)
                    bucket = "%s-%s" % (prefix,r)
                    test_s3_buckets.append(bucket)
                    bucket = "%s_%s" % (prefix,r)
                    test_s3_buckets.append(bucket)

print("Generated %s buckets to test" % len(test_s3_buckets))

init(autoreset=True)
i=0
public_buckets = []
private_buckets = []
#for bucket_name in test_s3_buckets:
#        print("testing bucket %s" % bucket_name)

def checkbucket(bucket_name):
    global i

    if bucket_name == "":
        return

    i += 1
    bucket_url = "https://%s.s3.amazonaws.com" % bucket_name
    res = get_page(bucket_url)

    if res.status_code == 200:
            print (Fore.RED + "[%s] %s " % ( res.status_code, bucket_name ))
            public_buckets.append("https://%s.s3.amazonaws.com" % bucket_name)
    elif res.status_code == 403:
            print (Fore.GREEN + "[%s] %s " % ( res.status_code, bucket_name ))
            private_buckets.append("https://%s.s3.amazonaws.com" % bucket_name)
    #else:
            #print (Style.DIM + "[%s] %s " % ( res.status_code, bucket_name ))

    #print ("Counter: %s" % i)
    percentage = round((float(i)/float(len(test_s3_buckets)))*100)
    if i%(int(len(test_s3_buckets)/7)) == 0:
        print("** %s%% complete... **" % percentage)


results = pool.map(checkbucket, test_s3_buckets)

public_buckets = set(public_buckets)
private_buckets = set(private_buckets)

print("The following buckets have been identified:")
print(Fore.RED + "[Public]")
for b in public_buckets:
        print (b)
print(Fore.GREEN + "[Private]")
for b in private_buckets:
        print (b)

print("--- %s seconds ---" % (time.time() - start_time))
