#!/usr/bin/env python3
import argparse
import logging
import re
import sys

from subprocess import run, TimeoutExpired, PIPE

# Nagios return codes: https://nagios-plugins.org/doc/guidelines.html#AEN78
OK = 0
WARNING = 1
CRITICAL = 2
UNKNOWN = 3


def get_args():
    '''
    Defining command-line arguments
    '''
    parser = argparse.ArgumentParser(description="Check network interface IP addresses")
    parser._optionals.title = "Options"
    parser.add_argument(
        '-a', '--address', nargs='+', required=True,
        help='network interface name and IP address, e.g. "enp1s0/192.168.0.10"',
        dest='ifaddresses', type=str)
    parser.add_argument(
        '-w', '--warning', nargs='?', required=False,
        help='list of network interface which only generate warnings, e.g. "enp2s0,enp7s0"',
        dest='warninglist', type=str)
    parser.add_argument(
        '-c', '--critical', nargs='?', required=False,
        help='list of network interfaces which always generate critical errors, e.g. "enp3s0,enp4s0"',
        dest='criticallist', type=str)
    parser.add_argument(
        '-v', '--verbose', required=False,
        help='enable verbose output', dest='verbose',
        action='store_true')
    parser.add_argument(
        '--log-file', nargs=1, required=False,
        help='file to log to, default: <stdout>',
        dest='logfile', type=str)

    args = parser.parse_args()

    return args


def get_logger(args: argparse.Namespace) -> logging.Logger:
    '''
    Defining logging
    '''
    if args.verbose:
        loglevel = logging.DEBUG
    else:
        loglevel = logging.INFO

    log_file = None
    if args.logfile:
        log_file = args.logfile[0]

    logging.basicConfig(filename=log_file,
                        format='%(levelname)s - %(message)s',
                        level=loglevel)

    return logging.getLogger(__name__)


def main():
    status = ""
    result = OK

    # Logging settings
    args = get_args()
    mylogger = get_logger(args)

    # Checking command line arguments
    if False:
        sys.exit(UNKNOWN)

    # Run check command for each network interface
    mylogger.debug(args.ifaddresses)
    for ifaddress in args.ifaddresses:
        try:
            interface, address = ifaddress.split("/")
        except ValueError:
            mylogger.error(f"Invalid interface address '{ifaddress}'")
            sys.exit(UNKNOWN)

        # Validity check for input parameters
        if interface == "" or address == "":
            mylogger.error(f"Invalid interface address '{ifaddress}'")
            sys.exit(UNKNOWN)
        if not re.match(r"^[a-z0-9]+$", interface):
            mylogger.error(f"Invalid interface '{interface}'")
            sys.exit(UNKNOWN)
        if not re.match(r"^-?[a-f0-9.:]+$", address):
            mylogger.error(f"Invalid address '{address}'")
            sys.exit(UNKNOWN)

        # Negate address by prepending "-"
        negate = False
        if address.startswith("-"):
            address = address[1:]
            negate = True

        # Run -o 'ip address show <interface>'
        try:
            cmd_df = ["ip", "-o", "address", "show", interface]
            mylogger.debug(f'Running OS command line: {cmd_df}')
            process = run(cmd_df, check=True, timeout=10, stdout=PIPE)
        except (OSError, TimeoutExpired, ValueError) as e:
            mylogger.warning(f'{e}')
            sys.exit(UNKNOWN)
        except Exception as e:
            mylogger.warning(f'Unexpected exception: {e}')
            sys.exit(UNKNOWN)

        # Parse output
        found = False

        for line in process.stdout.splitlines():
            (l_nr, l_ifname, l_proto, l_cidr, l_desc) = line.decode("utf-8").split(maxsplit=4)
            l_addr, l_subnet = l_cidr.split("/")

            if l_addr == address and l_ifname == interface:
                found = True

        # Create status message and result code
        if not found:
            if not negate:
                status += f"{address} missing for {interface};"
                result = CRITICAL
            else:
                status += f"{interface}/-{address};"
        else:
            if negate:
                status += f"{address} configured for {interface};"
                result = CRITICAL
            else:
                status += f"{interface}/{address};"

    # Print status message in Nagios format
    if result == OK:
        print(f"OK - {status}")
    elif result == WARNING:
        print(f"WARNING - {status}")
    elif result == CRITICAL:
        print(f"CRITICAL - {status}")

    sys.exit(result)

if __name__ == "__main__":
    main()
