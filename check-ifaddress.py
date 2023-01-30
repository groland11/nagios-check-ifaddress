#!/usr/bin/env python3
""" Nagios check for IP address on local network interface

Requirements
    Python >= 3.6
    Packages: -

This program is free software: you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation, either version 3 of the License, or (at your option) any later
version.

This program is distributed in the hope that it will be useful, but WITHOUT
ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
You should have received a copy of the GNU General Public License along with
this program. If not, see <http://www.gnu.org/licenses/>.
"""
import argparse
import logging
import re
import sys

from enum import Enum
from subprocess import run, TimeoutExpired, PIPE


__license__ = "GPLv3"
__version__ = "0.1"


# Check for minimum Python version
if not sys.version_info >= (3, 6):
    print("ERROR: Requires Python 3.6 or higher")
    exit(1)


# Nagios return codes: https://nagios-plugins.org/doc/guidelines.html#AEN78
class Result(Enum):
    OK = 0
    WARNING = 1
    CRITICAL = 2
    UNKNOWN = 3

    @classmethod
    def has_value(this, value):
        return value in [member.value for member in Result]


def get_args():
    '''
    Defining command-line arguments
    '''
    parser = argparse.ArgumentParser(description="Check network interface IP addresses")
    parser._optionals.title = "Options"
    parser.add_argument(
        '-a', '--address', nargs='+', required=True,
        help='network interface name and IP address, e.g. "enp1s0/192.168.0.10";'\
             'negate IP address by prepending a hyphen, e.g. "enp1s0/-192.168.0.11"',
        dest='ifaddresses', type=str)
    parser.add_argument(
        '-w', '--warning', nargs='?', required=False,
        help='list of network interface which only generate warnings, e.g. "enp2s0,enp7s0"',
        dest='warninglist', type=str)
    parser.add_argument(
        '-c', '--critical', nargs='?', required=False,
        help='list of network interfaces which always generate critical errors, e.g. "enp3s0,enp4s0" (default)',
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
    result = Result.OK
    result_error = Result.CRITICAL

    # Logging settings
    args = get_args()
    mylogger = get_logger(args)

    # Check command line arguments
    mylogger.debug(f"Warning for interfaces: {args.warninglist}")
    mylogger.debug(f"Critical for interfaces: {args.criticallist}")

    # Run check command for each network interface
    mylogger.debug(args.ifaddresses)
    for ifaddress in args.ifaddresses:
        try:
            interface, address = ifaddress.split("/")
        except ValueError:
            mylogger.error(f"Invalid interface address '{ifaddress}'")
            sys.exit(Result.UNKNOWN)

        # Validity check for input parameters
        if interface == "" or address == "":
            mylogger.error(f"Invalid interface address '{ifaddress}'")
            sys.exit(Result.UNKNOWN)
        if not re.match(r"^[a-z0-9]+$", interface):
            mylogger.error(f"Invalid interface '{interface}'")
            sys.exit(Result.UNKNOWN)
        if not re.match(r"^-?[a-f0-9.:]+$", address):
            mylogger.error(f"Invalid address '{address}'")
            sys.exit(Result.UNKNOWN)

        # Negate address by prepending "-"
        negate = False
        if address.startswith("-"):
            address = address[1:]
            negate = True

        # Warning or critical?
        if args.warninglist and interface in args.warninglist:
            result_error = Result.WARNING
        elif args.criticallist and interface in args.criticallist:
            result_error = Result.CRITICAL

        # Run 'ip -o address show <interface>'
        try:
            cmd_df = ["ip", "-o", "address", "show", interface]
            mylogger.debug(f'Running OS command line: {cmd_df}')
            process = run(cmd_df, check=True, timeout=10, stdout=PIPE)
        except (OSError, TimeoutExpired, ValueError) as e:
            mylogger.warning(f'{e}')
            sys.exit(Result.UNKNOWN)
        except Exception as e:
            mylogger.warning(f'Unexpected exception: {e}')
            sys.exit(Result.UNKNOWN)

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
                result = result_error
            else:
                status += f"{interface}/-{address};"
        else:
            if negate:
                status += f"{address} misconfigured for {interface};"
                result = result_error
            else:
                status += f"{interface}/{address} ok;"

    # Exit with Nagios result
    print(f"{result.name} - {status}")
    sys.exit(result.value)

if __name__ == "__main__":
    main()
