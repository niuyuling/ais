#!/bin/bash

cat info.txt | grep "Client Ip" | awk '{print $7}' | uniq -c

