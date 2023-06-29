#!/bin/bash

url=http://141.85.224.70:8086/admin.php

flag=$(curl -s -X POST -F 'username=admin' -F 'password=jukxoqnnca' -F 'secret=42'  $url | grep -o "MMM{.*}")

echo $flag
