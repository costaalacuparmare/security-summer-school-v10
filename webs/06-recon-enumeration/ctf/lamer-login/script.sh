#!/bin/bash

# Try to bruteforce username with SecList, the server tells you if only the username is correct
# allowing username enumeration. Then to the same with the password since u know th e username now


url='http://141.85.224.103:8081'
curl $url --data-raw 'username=abel&password=whatever&submit=Login' -s
