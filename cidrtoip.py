#!/usr/bin/env python
# This scripts converts a list of cidr notation IP ranges to /32 ip list. 
#
# $cat ip-range.list
# 192.168.0.0/24
# 10.0.0.1
#
# usage: ./cidrtoip.py -f ip-range.list
# 

import re
import sys
import os.path
import argparse
from netaddr import IPNetwork



parser = argparse.ArgumentParser()
parser.add_argument('--version', action='version', version='%(prog)s 0.1')
parser.add_argument('-f', action='store')
args = parser.parse_args()
fname = ''
if not args.f:
    print("File is required...")
    exit()
else:
    #check if file exists
    if os.path.isfile(args.f):
        print("file exists... reading file...")
        fname = args.f
    else:
        print("File '%s' does not exists" % args.f )
        exit()


#read the input file and remove spaces
with open(fname) as f:
    content = f.readlines()
# you may also want to remove whitespace characters like `\n` at the end of each line
content = [x.strip() for x in content]

for line in content:
    #print("Checking %s..." % line)
    try:
        for ip in IPNetwork(line):
            print("%s" % ip)
    except: # catch *all* exceptions
        e = sys.exc_info()[0]
        print ("Parsing %s" % ip)
        print( "<p>Error: %s</p>" % e )
        continue
