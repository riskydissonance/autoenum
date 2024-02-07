# Autoenum

Auto enumeration script used for CTFs.

## Requirements

- [nmap](https://nmap.org/)
- [katana](https://github.com/projectdiscovery/katana)
- [ffuf](https://github.com/ffuf/ffuf)

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
```