# Autoenum

Auto enumeration script used for CTFs.

## Requirements

- [nmap](https://nmap.org/)
- [katana](https://github.com/projectdiscovery/katana)
- [ffuf](https://github.com/ffuf/ffuf)
- [feroxbuster](https://github.com/epi052/feroxbuster)
- [csprecon](https://github.com/edoardottt/csprecon)

## Usage
```
CTF Auto Enumeration

options:
  -h, --help            show this help message and exit
  -i IP, --ip IP        the IP to connect to
  -o OUTPUT_DIR, --output-dir OUTPUT_DIR
                        the output directory
  -w WEB_PORT, --web-port WEB_PORT
                        just perform web checks on a provided port
  -s SSL, --ssl SSL     use ssl for web connections to the web-port
  -v, --verbose         verbose logging
  -p PROXY, --proxy PROXY
                        url to proxy web traffic through
  -r, --redirects       don't ignore redirects
  -a, --aggressive      aggressive mode, e.g. running feroxbuster
  -sw SUBDOMAIN_WORDLIST, --subdomain-wordlist SUBDOMAIN_WORDLIST
                        wordlist to use for subdomain proxying
  -dw DIRECTORY_WORDLIST, --directory-wordlist DIRECTORY_WORDLIST
                        wordlist to use for directory brute forcing
```