#!/bin/bash
#
# GET info
# date 20200526
#

cat info.txt | grep "Client Ip" | awk '{print $7}' | uniq -c

