#!/bin/bash

openssl x509 -noout -text -inform der -in example.der | grep -o 'SSS{.*}'
