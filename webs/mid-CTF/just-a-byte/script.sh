#!/bin/bash

#it requires to try each possible byte (1-256) in hexa and see which works

while IFS= read -r hex
do
  url="http://141.85.224.118:5005/byt3" 
 flag=$(curl -s "$url" --data-raw "message=$hex&msg=$hex" | grep -o "SSS{.*}")
 echo $flag
done < hexa.txt
