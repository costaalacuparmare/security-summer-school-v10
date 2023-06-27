### IP Destroyer
```
Based on the fact that the site executes a ping commands it means that the IP for the ping can be used to send
commands to the server. Testing with `; echo "Hello world"` and seeing that it prints Hello world i started trying
other commands, such as ls, pwd and grep. Using `grep -r "SSS" /` u printed all the lines in the shell that contain
this string, therefore finding the flag
```
