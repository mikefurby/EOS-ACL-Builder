"""
DESCRIPTION
Script that will remove ACLs o

examples:
Remove the ACL called 'testacl' from switch 's7282'
python3 aclremove.py -s s7282 -n testacl 

Ask for help
python3 aclremove.py -h
python3 aclremove.py --help
"""

__author__ = 'Mike Furby (mfurby@arista.com)'

import pyeapi
import argparse

def acl_loop(node,acln):
    print (acln)
    acls = node.api('acl')
    acls.delete(acln)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-s", "--switch", required=True,
        help="Switch Hostname as input into .eapi.conf in the root directory")
    ap.add_argument("-n", "--name", required=True,
        help="Name of the ACL")
    args = vars(ap.parse_args())

    hostname = (args['switch'])
    acl_name = (args['name'])

    node = pyeapi.connect_to(hostname)       #needs the .eapi.conf file in the /home/ directory
    print (node.enable('show hostname'))     #just use eapi to get the hostname and confirm connectivity
    acl_loop(node,acl_name)     #use the function abover to do the ACL

if __name__ == '__main__':
    main()
