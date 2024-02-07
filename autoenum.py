import argparse
import os
import subprocess
import asyncio
import sys

WEB_PORTS = [80, 443]


class Logger:
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    RED = '\033[91m'
    ENDC = '\033[0m'

    @staticmethod
    def info(message):
        print("[%s*%s] %s" % (Logger.BLUE, Logger.ENDC, message))

    @staticmethod
    def success(message):
        print("[%s+%s] %s" % (Logger.GREEN, Logger.ENDC, message))

    @staticmethod
    def failure(message):
        print("[%s-%s] %s" % (Logger.RED, Logger.ENDC, message))


def create_arg_parser():
    parser = argparse.ArgumentParser(description='CTF Auto Enumeration')
    parser.add_argument('-i', '--ip', type=str, help='the IP to connect to')
    parser.add_argument('-o', '--output-dir', type=str, help='the output directory')
    parser.add_argument('-w', '--web-port', type=str, help='just perform web checks on a provided port')
    parser.add_argument('-s', '--ssl', type=str, help='use ssl for web connections to the web-port')
    parser.add_argument('-v', '--verbose', help='verbose logging', action='store_true')
    return parser


def port_scan(ip, output_dir, verbose) -> (str, []):
    Logger.info(f'All TCP port scan of {ip}')
    cmd = f'sudo nmap -v -sS -Pn -n -p- -n --min-rate=10000 -oA {output_dir}/nmap-tcp-quick-{ip} {ip}'
    if verbose:
        Logger.info(f'Running: {cmd}')
    quick_scan_output = (subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True)
                         .stdout.decode('utf-8'))
    if verbose:
        print(quick_scan_output)
    open_ports = []
    for line in quick_scan_output.split('\n'):
        if "/tcp open" in line:
            open_ports.append(line.split('/')[0])
    Logger.info(f'Open ports on {ip}: {",".join(open_ports)}')
    host = "localhost"
    Logger.info(f'Focused TCP port scan of {ip}, ports: {",".join(open_ports)}')
    cmd = f'sudo nmap -v -sCV -Pn -n -p {",".join(open_ports)} -n -oA {output_dir}/nmap-tcp-full-{ip} {ip}'
    if verbose:
        Logger.info(f'Running: {cmd}')
    full_scan_output = (
        subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True).stdout.decode('utf-8'))
    if verbose:
        print(full_scan_output)
    return host, open_ports


async def web_crawl(host, port, output_dir, verbose) -> []:
    Logger.info(f'Web crawling {host}:{port}')
    # Katana
    pass


async def subdomain_enum(host, port, output_dir, verbose):
    Logger.info(f'Subdomain enum: {host}:{port}')
    # ffuf subdomain enum
    pass


async def directory_brute_force(host, port, output_dir, verbose):
    Logger.info(f'Directory brute forcing: {host}:{port}')
    # ffuf subdomain brute force
    pass


async def web_scan(host, output_dir, port, verbose):
    Logger.info(f'Web scanning {host}:{port}')
    crawl = web_crawl(host, port, output_dir, verbose)
    brute_force = directory_brute_force(host, port, output_dir, verbose)
    subdomain_enum = subdomain_enum(host, port, output_dir, verbose)
    await asyncio.gather(crawl, brute_force, subdomain_enum)


async def main():
    parser = create_arg_parser()
    args = parser.parse_args()

    if not args.ip:
        Logger.failure(f'--ip is required')
        sys.exit(1)

    output_dir = args.output_dir

    if not args.output_dir:
        output_dir = os.getcwd()

    if args.ssl and not args.web_port:
        Logger.failure(f'Cannot use --ssl without --web-port')
        sys.exit(1)

    Logger.info(f'Saving output to {output_dir}')

    if args.web_port:
        await web_scan(args.ip, output_dir, args.web_port, args.verbose)
        return

    (host, open_ports) = port_scan(args.ip, output_dir, args.verbose)
    tasks = []
    for port in WEB_PORTS:
        if port in open_ports:
            tasks.append(web_scan(host, output_dir, port, args.verbose))

    await asyncio.gather(*tasks)


if __name__ == '__main__':
    asyncio.run(main())
