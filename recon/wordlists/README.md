# Wordlists

## Subdomain Wordlist

Download a good subdomain wordlist before running the pipeline:

```bash
# SecLists (recommended — comprehensive)
wget -O subdomains.txt https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-110000.txt

# OR: assetnote best-dns (aggressive, larger)
wget -O subdomains.txt https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt

# OR: smaller / faster option
wget -O subdomains.txt https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt
```

## Resolvers

`resolvers.txt` contains reliable public DNS resolvers. For best results with puredns, use a validated resolver list:

```bash
# dnsvalidator — generates a fresh trusted resolver list
dnsvalidator -tL https://public-dns.info/nameservers.txt -threads 100 -o resolvers.txt
```

## Content Discovery Wordlists

For feroxbuster/ffuf/gobuster, use these:

```bash
# General web content
wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-medium-directories.txt

# API-focused
wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/api/api-endpoints.txt

# Tesla-specific (build this as you discover patterns)
# Add custom paths you find during testing to tesla-custom.txt
```
