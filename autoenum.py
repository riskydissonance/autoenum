import argparse
import os
import re
import subprocess
import asyncio
import sys

URL_REGEX = re.compile(r".*https?:\/\/([a-zA-Z0-9\.]+)")
NMAP_OPEN_PORT_LINE_REGEX = re.compile(r"^\d+/tcp\s+open")
FFUF_REGEX = re.compile(r".*\[2K(\S+)\s*\[Status: (\d+), Size: (\d+),")
IP_REGEX = re.compile(r"\d+\.\d+\.\d+\.\d+")
CSPRECON_REGEX = re.compile(r"^(\w+)")
AUTOENUM_LOG_FILE = "/autoenum.log"
USER_AGENT = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 11_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36'


class Logger:
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    RED = '\033[91m'
    ENDC = '\033[0m'

    @staticmethod
    def highlight(message, output_dir):
        log = "\n[%s+%s] %s%s%s" % (Logger.GREEN, Logger.ENDC, Logger.GREEN, message, Logger.ENDC)
        print(log + "\n")
        with open(output_dir + AUTOENUM_LOG_FILE, 'a') as f:
            f.write(log + "\n")

    @staticmethod
    def info(message, output_dir):
        log = "[%s*%s] %s" % (Logger.BLUE, Logger.ENDC, message)
        print(log)
        with open(output_dir + AUTOENUM_LOG_FILE, 'a') as f:
            f.write(log + "\n")

    @staticmethod
    def success(message, output_dir):
        log = "[%s+%s] %s" % (Logger.GREEN, Logger.ENDC, message)
        print(log)
        with open(output_dir + AUTOENUM_LOG_FILE, 'a') as f:
            f.write(log + "\n")

    @staticmethod
    def failure(message, output_dir):
        log = "[%s-%s] %s" % (Logger.RED, Logger.ENDC, message)
        print(log)
        with open(output_dir + AUTOENUM_LOG_FILE, 'a') as f:
            f.write(log + "\n")


def create_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description='CTF Auto Enumeration')
    parser.add_argument('-i', '--ip', type=str, help='the IP to connect to')
    parser.add_argument('-o', '--output-dir', type=str, help='the output directory')
    parser.add_argument('-w', '--web-port', type=str, help='just perform web checks on a provided port')
    parser.add_argument('-s', '--ssl', type=str, help='use ssl for web connections to the web-port')
    parser.add_argument('-v', '--verbose', help='verbose logging', action='store_true')
    parser.add_argument('-p', '--proxy', help='url to proxy web traffic through')
    parser.add_argument('-r', '--redirects', help='don\'t ignore redirects', action='store_true')
    parser.add_argument('-a', '--aggressive', help='aggressive mode, e.g. running feroxbuster', action='store_true')
    parser.add_argument('-sw', '--subdomain-wordlist', help='wordlist to use for subdomain proxying',
                        default='/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt')
    parser.add_argument('-dw', '--directory-wordlist', help='wordlist to use for directory brute forcing',
                        default='/usr/share/seclists/Discovery/Web-Content/common.txt')
    return parser


def port_scan(ip, output_dir, verbose) -> (str, []):
    Logger.info(f'[Portscan] Quick all TCP port scan of {ip}', output_dir)
    open_ports = quick_scan(ip, output_dir, verbose)
    if not open_ports:
        Logger.failure(f"[Portscan] No open ports found on {ip}", output_dir)
        sys.exit(1)
    Logger.highlight(f'[Portscan] Open ports on {ip}: {",".join(open_ports)}', output_dir)
    full_scan_output = full_port_scan(ip, open_ports, output_dir, verbose)
    host = ip
    web_ports = []
    redirect_line = None
    for line in full_scan_output.split('\n'):
        if "Did not follow redirect to " in line:
            redirect_line = line
        if line.startswith("|"):
            Logger.success(f"[Portscan] {line.strip()}", output_dir)
        if NMAP_OPEN_PORT_LINE_REGEX.match(line):
            Logger.success(f"[Portscan] {line.strip()}", output_dir)
            if "ssl/https" in line:
                web_ports.append((line.split("/")[0], True))
            elif "http" in line:
                web_ports.append((line.split("/")[0], False))
    if redirect_line is not None:
        host = URL_REGEX.match(redirect_line).group(1)
        Logger.info(f'[Portscan] Got redirect to {host}', output_dir)
        with open('/etc/hosts', 'r') as f:
            contents = f.read()
            if host not in contents:
                Logger.info("[Portscan] Host not in /etc/hosts file, adding now", output_dir)
                cmd = f"echo '{ip} {host}' >> /etc/hosts"
                run_command(cmd, output_dir, verbose)
            else:
                Logger.info("[Portscan] Host already in /etc/hosts file", output_dir)

        Logger.info(f'[Portscan] Rerunning scripting nmap scan on new host', output_dir)
        full_port_scan(host, open_ports, output_dir, verbose)
    return host, open_ports, web_ports


def quick_scan(ip, output_dir, verbose) -> [str]:
    cmd = f'nmap -v -sS -Pn -n -p- -n --min-rate=10000 -oA {output_dir}/nmap-tcp-quick-{ip} {ip}'
    output = run_command(cmd, output_dir, verbose)
    open_ports = []
    for line in output.split('\n'):
        if NMAP_OPEN_PORT_LINE_REGEX.match(line):
            open_ports.append(line.split('/')[0])
    return open_ports


def run_command(cmd, output_dir, verbose) -> str:
    if verbose:
        Logger.info(f'[Exec] Running: {cmd}', output_dir)
    output = (subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True)
              .stdout.decode('utf-8'))
    if verbose:
        print(output)
    return output


def full_port_scan(host, open_ports, output_dir, verbose) -> str:
    Logger.info(f'[Portscan] Focused TCP port scan of {host}, ports: {",".join(open_ports)}', output_dir)
    cmd = f'nmap -v -sCV -Pn -n -p {",".join(open_ports)} -n -oA {output_dir}/nmap-tcp-full-{host} {host}'
    output = run_command(cmd, output_dir, verbose)
    return output


async def check_csp(host, port, ssl, output_dir, proxy, verbose) -> [str]:
    url = build_url(host, port, ssl)
    Logger.info(f'[CSP Recon] Checking CSP for subdomains for: {url}', output_dir)
    cmd = f"csprecon -u {url} -o {output_dir}/csprecon-{host}-{port}.log"
    output = run_command(cmd, output_dir, verbose)
    found = []
    for line in output.split('\n'):
        match = CSPRECON_REGEX.match(line)
        if match:
            subdomain = match.group(1)
            Logger.highlight(f'[CSP Recon] Found subdomain: {subdomain}', output_dir)
            found.append(subdomain)
    return found


async def web_crawl(host, port, ssl, output_dir, proxy, verbose) -> [str]:
    url = build_url(host, port, ssl)
    Logger.info(f'[Crawler] Web crawling {url}', output_dir)
    cmd = f'katana -u {url} -o {output_dir}/katana-{host}-{port}.log -jc -kf all -fx'
    if proxy:
        cmd += f" -proxy {proxy}"
    output = run_command(cmd, output_dir, verbose)
    found = []
    for line in output.split("\n"):
        if line.startswith("http"):
            Logger.success(f"[Crawler] Found: {line.strip()}", output_dir)
            found.append(line.strip())
    return found


def build_url(host, port, ssl) -> str:
    if ssl:
        url = f'https://{host}:{port}'
    else:
        url = f'http://{host}:{port}'
    return url


async def subdomain_enum(host, port, ssl, output_dir, wordlist, show_redirects, verbose) -> [str]:
    found = []
    if IP_REGEX.match(host):
        Logger.info(f"[Subdomain Enum] Skipping subdomain enum for IP: {host}", output_dir)
        return found
    Logger.info(f'[Subdomain Enum] Starting enum: {host}:{port}', output_dir)
    url = build_url(host, port, ssl)
    cmd = f'ffuf -u {url} -w {wordlist} -H "Host: FUZZ.{host}" -of md -o {output_dir}/ffuf-subdomain-enum-{host}-{port}.md'
    if not show_redirects:
        cmd += ' -fc 302,301'
    output = run_command(cmd, output_dir, verbose)
    for line in output.split('\n'):
        match = FFUF_REGEX.match(line.strip())
        if match:
            subdomain = match.group(1)
            http_code = match.group(2)
            size = match.group(3)
            Logger.highlight(f"[Subdomain Enum] Found: {subdomain}.{host} (Code: {http_code}, Size: {size})",
                             output_dir)
            found.append(f"{subdomain}.{host}")
    return found


async def url_brute_force(host, port, ssl, output_dir, proxy, wordlist, show_redirects, verbose) -> [str]:
    url = build_url(host, port, ssl)
    Logger.info(f'[URL Brute Force] Brute forcing: {url}', output_dir)
    cmd = f'ffuf -u {url}/FUZZ -w {wordlist} -of md -o {output_dir}/ffuf-dirb-{host}-{port}.md'
    if not show_redirects:
        cmd += ' -fc 302,301'
    if proxy:
        cmd += f" -x {proxy}"
    output = run_command(cmd, output_dir, verbose)
    found = []
    for line in output.split('\n'):
        match = FFUF_REGEX.match(line)
        if match:
            directory = match.group(1)
            http_code = match.group(2)
            size = match.group(3)
            Logger.success(f"[URL Brute Force] Found: {url}/{directory} (Code: {http_code}, Size: {size})", output_dir)
            found.append(directory)
    return found


async def web_scan(host, port, ssl, output_dir, proxy, subdomain_wordlist, directory_wordlist, show_redirects, verbose) -> [str]:
    if host.startswith("*"):
        Logger.failure("[Web] Wildcard domains are not supported and will have to be investigated manually", output_dir)
        return
    crawl = web_crawl(host, port, ssl, output_dir, proxy, verbose)
    brute_force = url_brute_force(host, port, ssl, output_dir, proxy, directory_wordlist, show_redirects, verbose)
    subdomains = await check_csp(host, port, ssl, output_dir, proxy, verbose)
    subdomains.extend(await subdomain_enum(host, port, ssl, output_dir, subdomain_wordlist, show_redirects, verbose))
    tasks = []
    subdomains = set(subdomains)
    for subdomain in subdomains:
        tasks.append(
            web_scan(subdomain, port, ssl, output_dir, proxy, subdomain_wordlist, directory_wordlist, show_redirects,
                     verbose))
    await asyncio.gather(crawl, brute_force)
    await asyncio.gather(*tasks)
    return subdomains


async def aggressive_content_discovery(host, port, ssl, output_dir, proxy, verbose):
    url = build_url(host, port, ssl)
    Logger.info(f'[Aggressive] Starting scan of {url}', output_dir)
    cmd = f"feroxbuster -u {url} --auto-tune -o {output_dir}/feroxbuster-{host}-{port}.log -a '{USER_AGENT}'"
    if proxy:
        cmd += f" --proxy {proxy} --insecure"
    if verbose:
        Logger.info(f'[Aggressive] Running: {cmd}', output_dir)
    subprocess.run(cmd, shell=True)


async def main():
    parser = create_arg_parser()
    args = parser.parse_args()

    output_dir = args.output_dir
    if not args.output_dir:
        output_dir = os.getcwd()

    if not os.geteuid() == 0:
        Logger.failure('This script must be run as root', output_dir)
        sys.exit(1)

    if not args.ip:
        Logger.failure('--ip is required', output_dir)
        sys.exit(1)

    if args.ssl and not args.web_port:
        Logger.failure(f'Cannot use --ssl without --web-port', output_dir)
        sys.exit(1)

    Logger.info(f'Saving output to {output_dir}', output_dir)

    if os.path.exists(f"{output_dir}{AUTOENUM_LOG_FILE}"):
        os.remove(f"{output_dir}{AUTOENUM_LOG_FILE}")

    if args.web_port:
        await web_scan(args.ip, args.web_port, args.ssl, output_dir, args.proxy, args.subdomain_wordlist,
                       args.directory_wordlist, args.redirects, args.verbose)
        return

    (host, open_ports, web_ports) = port_scan(args.ip, output_dir, args.verbose)
    tasks = []
    # TODO capture discovered subdomains for feroxbuster
    subdomains = []
    for (port, ssl) in web_ports:
        tasks.append(
            web_scan(args.ip, port, ssl, output_dir, args.proxy, args.subdomain_wordlist, args.directory_wordlist,
                     args.redirects, args.verbose))
        if host != port:
            tasks.append(
                web_scan(host, port, ssl, output_dir, args.proxy, args.subdomain_wordlist, args.directory_wordlist,
                         args.redirects, args.verbose))

    await asyncio.gather(*tasks)
    Logger.highlight("Done!", output_dir)
    tasks = []

    if args.aggressive:
        Logger.info('[Aggressive] Starting aggressive scans', output_dir)
        for (port, ssl) in web_ports:
            tasks.append(
                aggressive_content_discovery(host, port, ssl, output_dir, args.proxy, args.verbose))
            if host != args.ip:
                tasks.append(
                    aggressive_content_discovery(args.ip, port, ssl, output_dir, args.proxy, args.verbose))

        await asyncio.gather(*tasks)
        Logger.highlight("Aggressive scans done!", output_dir)


if __name__ == '__main__':
    asyncio.run(main())
