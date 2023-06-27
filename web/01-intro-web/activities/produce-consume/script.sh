#!/bin/bash
curl -s -c cookies.txt -o dev/null http://141.85.224.70:8091/produce-consume/produce.php
phpsessid=$(cat cookies.txt | grep PHPSESSID | awk '{print $7}')
curl -s -b 'PHPSESSID='$phpsessid'' http://141.85.224.70:8091/produce-consume/consume.php
