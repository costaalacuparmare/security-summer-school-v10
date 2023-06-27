### Sequel Pro
```
Using the credentials given, it was clear that the secret of each user was not crypted and easily found in HTML code.
Trying different SQL commands in the username bracked, the errors the login.php returned alluded to the vulnerability
being exploitable with SQL Injection. Trying `' OR 1=1 #` I succeded in logging in as admin and finding the flag
```
