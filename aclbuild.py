import sys
import pyeapi
import pprint
import json
import time
import argparse

def acl_loop(acln,src,mask,maxrules,action,dst,dmask,node):
    print (acln,src,mask,maxrules,action,dst,dmask,node)

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
    print ("checking address")
    if mask <= 32:
        net = (int(d_low_address / blocksize[d_index]))        
        d_low_address = int(net * blocksize[d_index])         
    if mask <= 24:
        net = (int(c_low_address / blocksize[c_index]))        
        c_low_address = int(net * blocksize[c_index])         
    if mask <= 16:
        net = (int(b_low_address / blocksize[b_index]))        
        b_low_address = int(net * blocksize[b_index])         
    if mask <= 8:
        net = (int(a_low_address / blocksize[a_index]))        
        a_low_address = int(net * blocksize[a_index])         
    print (a_low_address, b_low_address, c_low_address, d_low_address, mask)
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
                    acls.add_entry(acln,action,"ip",src_ip,mask,dst,dmask)
                    print (acln,action,"ip",src_ip,mask,dst,dmask)

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

def connect_to_switch(node):
# add stuff here for switch queries if you want, otherwise it doesn't do much
    print (node.enable('show hostname'))

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-s", "--switch", required=True,
        help="Switch Hostname as input into .eapi.conf in the root directory")
    ap.add_argument("-n", "--name", required=True,
        help="Name of the ACL")
    ap.add_argument("-i", "--ipsrc", required=True,
        help="First IP address in the ACL")
    ap.add_argument("-m", "--mask", required=True,
        help="Subnet mask")
    ap.add_argument("-r", "--rules", required=True,
        help="Number of rules to add")
    ap.add_argument("-a", "--action", required=True,
        help="Rule action = 'permit' or 'deny'")
    ap.add_argument("-d", "--ipdst", required=False,
        help="Destination IP, default = 0.0.0.0")
    ap.add_argument("-M", "--dmask", required=False,
        help="Destination Mask, default = 0")
    args = vars(ap.parse_args())

    hostname = (args['switch'])
    acl_name = (args['name'])
    first_src = (args['ipsrc'])
    src_netmask = int(args['mask'])
    max_rules = int(args['rules'])
    rule_action = (args['action'])

    try:
        dst_ip = (args['ipdst'])
        dst_mask = int(args['dmask'])
    except:
        dst_ip = '0.0.0.0'
        dst_mask = 0

    try:
        node = pyeapi.connect_to(hostname)       #needs the .eapi.conf file in the /home/ directory
        connect_to_switch(node)
        acl_loop(acl_name,first_src,src_netmask,max_rules,rule_action,dst_ip,dst_mask,node)
    except:
        print ("Execution Failed:")
        print ("check the .eapi.conf file for the correct hostname")


if __name__ == '__main__':
    main()
