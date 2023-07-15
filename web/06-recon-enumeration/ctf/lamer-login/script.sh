#!/bin/bash
url='http://141.85.224.103:8081'
curl $url --data-raw 'username=abel&password=whatever&submit=Login' -s
