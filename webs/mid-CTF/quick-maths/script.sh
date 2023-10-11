#!/bin/bash

#In the main.js u find something that looks like hexa, decode it into text and u get "googolplex.php" add that 
#to the url and u get some math. Do the math and u get 453313424. add that to the http request as referal

curl -H "Referer: 453313424" "http://141.85.224.106:8082/index.php" | grep -o "SSS{.*}"
