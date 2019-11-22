#!/usr/bin/python
import sys
import pyeapi
import pprint
import json
import time


def acl_loop(acln,maxrules,src,mask):
    print (acln)
    a_low_address = int(src.split(".")[0])
    b_low_address = int(src.split(".")[1])
    c_low_address = int(src.split(".")[2])
    d_low_address = int(src.split(".")[3])
    a_high_address = 255
    b_high_address = 255
    c_high_address = 255 
    d_high_address = 255
    rule_count = 0
    a_count = 0
    b_count = 0
    c_count = 0
    d_count = 0

    blocksize = (256,128,64,32,16,8,4,2,1)
    a_maskindex = (0,1,2,3,4,5,6,7,8,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0)
    b_maskindex = (0,0,0,0,0,0,0,0,0,1,2,3,4,5,6,7,8,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0)
    c_maskindex = (0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,2,3,4,5,6,7,8,0,0,0,0,0,0,0,0)
    d_maskindex = (0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,2,3,4,5,6,7,8)
    a_index = (a_maskindex[mask])
    b_index = (b_maskindex[mask])
    c_index = (c_maskindex[mask])
    d_index = (d_maskindex[mask])

##ensures that the input source address is a valid subnet for the mask used
##it doesn't matter if it isn't because EOS converts to a valid network address
##However, it is nice to fix it anyway.
    if mask <= 32:
        net = (d_low_address / blocksize[d_index])        
        d_low_address = (net * blocksize[d_index])         
    if mask <= 24:
        net = (c_low_address / blocksize[c_index])        
        c_low_address = (net * blocksize[c_index])         
    if mask <= 16:
        net = (b_low_address / blocksize[b_index])        
        b_low_address = (net * blocksize[b_index])         
    if mask <= 8:
        net = (a_low_address / blocksize[a_index])        
        a_low_address = (net * blocksize[a_index])         
#    print (a_low_address, b_low_address, c_low_address, d_low_address, mask)
#    time.sleep(60)

    acls = node.api('acl')
    acls.create(acln,type='extended')
    acls.add_entry(acln,"no permit","ip","0.0.0.0","0","0.0.0.0","0")
    print (acln,"no permit","ip","0.0.0.0","0","0.0.0.0","0")

    block_a = a_low_address
    while block_a <= a_high_address:
        a_count += 1
        if rule_count > maxrules:
            print ("break")
            break
        if b_count != 0:
            block_b = 0
        else:
            block_b = b_low_address
        while block_b <= b_high_address:
            b_count += 1
            if rule_count > maxrules:
                print ("break")
                break
            if c_count != 0:
                block_c = 0
            else:
                block_c = c_low_address
            while block_c <= c_high_address:
                c_count += 1
                if rule_count > maxrules:
                    print ("break")
                    break
                if d_count != 0:
                    block_d = 0
                else:
                    block_d = d_low_address
                while block_d <= d_high_address:
                    rule_count += 1
                    d_count += 1
                    print ("Rules configured: " + str(rule_count) + " " + str(maxrules))
                    if rule_count > maxrules:
                        print ("break")
                        break
                    cba = (str(block_a) + ".")
                    cbb = (str(block_b) + ".")
                    cbc = (str(block_c) + ".")
                    cbd = (str(block_d))
                    src_ip = (cba + cbb + cbc + cbd)
                    acls.add_entry(acln,"deny","ip",src_ip,mask,"0.0.0.0","0")
                    print (acln,"deny","ip",src_ip,mask,"0.0.0.0","0")

                    if mask >= 24:
                      block_d += (blocksize[d_index])
                    elif mask >= 16:
                      block_c += (blocksize[c_index]-1)
                      block_d = 256
                    elif mask >= 8:
                      block_b += (blocksize[b_index]-1)
                      block_c = 255
                      block_d = 256
                    elif mask >= 0:
                      block_a += (blocksize[a_index]-1)
                      block_b = 255
                      block_c = 255
                      block_d = 256

                block_c += 1
                block_d = 0
            block_b += 1
            block_c = 0
        block_a += 1
        block_b = 0
    acls.add_entry(acln,"permit","ip","0.0.0.0","0","0.0.0.0","0")
    print (acln,"permit","ip","0.0.0.0","0","0.0.0.0","0")


####main
if len( sys.argv ) <= 5:   #check the arguements into the script
    sys.stderr.write("example syntax, one arguement is required \n")
    sys.stderr.write("./aclbuild1 <hostname> <ACL_name> <ip_src> <netmask> <#rules>\n")
    sys.exit(1)

hostname = sys.argv[1]         #i.e. cal362 or s70512
acl_name = sys.argv[2]         #i.e. port_mirror_acl1
first_src = sys.argv[3]        #i.e. 1.1.1.0
src_netmask = int(sys.argv[4]) #i.e. 24
max_rules = int(sys.argv[5])   #i.e. 100

node = pyeapi.connect_to(hostname)       #needs the .eapi.conf file in the /home/ directory
print (node.enable('show hostname'))     #just use eapi to get the hostname and confirm connectivity
acl_loop(acl_name,max_rules,first_src,src_netmask)     #use the function abover to do the ACL
# the end
