#!/bin/bash

username='admin'
password='Password123$'

curl -s -X GET http://141.85.224.70:8087'/login?username='$username'&password='$password
