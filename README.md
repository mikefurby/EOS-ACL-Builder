# EOS-ACL-Builder
Script to build ACLs and programme EOS switches using eAPI

Uses pyeapi (https://pyeapi.readthedocs.io/en/latest/)
Read the docs to create the .eapi.conf file

Will build ACLS as follows. You can build multiple ACLs, or add to existing ones. the example here is of addition to existing
On each execution, the script removes the explicit permit any/any first, then writes the new rules before adding the explicit permit any/any back on.
This is the result of multiple executions to the same ACL name:

ip access-list testacl
   10 deny ip 1.2.3.0/24 any
   20 deny ip 1.2.4.0/24 any
   30 deny ip 1.2.5.0/24 any
   40 deny ip 1.2.3.0/24 any
   50 deny ip host 1.2.3.4 any
   60 deny ip host 1.2.3.5 any
   70 deny ip host 1.2.3.6 any
   80 deny ip 1.2.3.4/31 any
   90 deny ip 1.2.3.6/31 any
   100 deny ip 1.2.3.8/31 any
   110 deny ip 1.2.3.4/30 any
   120 deny ip 1.2.3.8/30 any
   130 deny ip 1.2.3.12/30 any
   140 deny ip 1.2.3.0/29 any
   150 deny ip 1.2.3.8/29 any
   160 deny ip 1.2.3.16/29 any
   170 deny ip 1.2.3.0/28 any
   180 deny ip 1.2.3.16/28 any
   190 deny ip 1.2.3.32/28 any
   200 deny ip 1.2.3.0/27 any
   210 deny ip 1.2.3.32/27 any
   220 deny ip 1.2.3.64/27 any
   230 deny ip 1.2.3.0/26 any
   240 deny ip 1.2.3.64/26 any
   250 deny ip 1.2.3.128/26 any
   260 deny ip 1.2.3.0/25 any
   270 deny ip 1.2.3.128/25 any
   280 deny ip 1.2.4.0/25 any
   290 deny ip 1.2.2.0/23 any
   300 deny ip 1.2.4.0/23 any
   310 deny ip 1.2.6.0/23 any
   320 deny ip 1.2.0.0/22 any
   330 deny ip 1.2.4.0/22 any
   340 deny ip 1.2.8.0/22 any
   350 deny ip 1.2.0.0/22 100.1.2.0/24
   360 deny ip 1.2.4.0/22 100.1.2.0/24
   370 deny ip 1.2.8.0/22 100.1.2.0/24
   380 deny ip 1.2.12.0/22 100.1.2.0/24
   390 deny ip 1.2.16.0/22 100.1.2.0/24
   400 deny ip 1.2.20.0/22 100.1.2.0/24
   410 deny ip 1.2.24.0/22 100.1.2.0/24
   420 deny ip 1.2.28.0/22 100.1.2.0/24
   430 deny ip 1.2.32.0/22 100.1.2.0/24
   440 deny ip 1.2.36.0/22 100.1.2.0/24
   450 permit ip any any
