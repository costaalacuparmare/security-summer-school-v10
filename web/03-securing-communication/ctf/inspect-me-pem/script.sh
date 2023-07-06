#!/bin/bash

openssl x509 -noout -text -in example.crt | grep -o 'SSS{.*}'
