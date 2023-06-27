#!/bin/bash

data=$(tr -dc A-Za-z0-9 < /dev/urandom | head -c 35)
curl -s -X POST -H "Content-Type: text/plain" --data $data http://141.85.224.70:8082/gimme
