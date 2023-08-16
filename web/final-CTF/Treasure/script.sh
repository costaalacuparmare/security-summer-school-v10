#!/bin/bash

for l in $(cat key | grep '^| ---' | sed 's/^.*-----BEGIN RSA PRIVATE KEY----- \(.*\) -----END RSA PRIVATE KEY-----.*$/\1/'); do
    (echo "-----BEGIN RSA PRIVATE KEY-----"
    sed 's/ /\n/g' <<<"$l"
    echo "-----END RSA PRIVATE KEY-----") > priv.key
done
