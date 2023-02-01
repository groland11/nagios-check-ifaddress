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


# Global logging object
logger = logging.getLogger(__name__)


# Nagios return codes: https://nagios-plugins.org/doc/guidelines.html#AEN78
class Result(Enum):
    OK = 0
    WARNING = 1
    CRITICAL = 2
    UNKNOWN = 3

    @classmethod
    def has_value(this, value):
        return value in [member.value for member in Result]

class LogFilterWarning(logging.Filter):
    """Logging filter = INFO, WARNING"""
    def filter(self, record):
        return record.levelno in {logging.INFO, logging.WARNING}

class LogFilterDebug(logging.Filter):
    """Logging filter = DEBUG"""
    def filter(self, record):
        return record.levelno in {logging.DEBUG}

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
        '-w', '--warning', required=False,
        help='list of network interface which only generate warnings, e.g. "enp2s0,enp7s0"',
        dest='warninglist', type=str)
    parser.add_argument(
        '-c', '--critical', required=False,
        help='list of network interfaces which always generate critical errors, e.g. "enp3s0,enp4s0" (default)',
        dest='criticallist', type=str)
    parser.add_argument(
        '-v', '--verbose', required=False,
        help='enable verbose output', dest='verbose',
        action='store_true')
    parser.add_argument(
        '--logfile', nargs=1, required=False,
        help='log verbose output into logfile, default: <stdout>',
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

    logger.setLevel(loglevel)

    # Log everything >= INFO to stdout
    h1 = logging.StreamHandler(sys.stdout)
    h1.setLevel(logging.INFO)
    h1.setFormatter(logging.Formatter(fmt='%(asctime)s [%(process)d] %(levelname)s: %(message)s',
                                      datefmt='%Y-%m-%d %H:%M:%S'))
    h1.addFilter(LogFilterWarning())

    # Log errors to stderr
    h2 = logging.StreamHandler(sys.stderr)
    h2.setFormatter(logging.Formatter(fmt='%(asctime)s [%(process)d] %(levelname)s: %(message)s',
                                      datefmt='%Y-%m-%d %H:%M:%S'))
    h2.setLevel(logging.ERROR)

    # Log everything = DEBUG to logfile or stdout
    if args.logfile:
        logfile = args.logfile[0]
        try:
            h3 = logging.FileHandler(logfile, encoding="utf-8")
        except FileNotFoundError as e:
            logger.error(f"Invalid logfile ({e})")
    else:
        h3 = logging.StreamHandler(sys.stdout)

    h3.setLevel(logging.DEBUG)
    h3.setFormatter(logging.Formatter(fmt='%(asctime)s [%(process)d] %(levelname)s: %(message)s',
                                      datefmt='%Y-%m-%d %H:%M:%S'))
    h3.addFilter(LogFilterDebug())

    # Add all 3 handlers (stdout, stderr, debug)
    logger.addHandler(h1)
    logger.addHandler(h2)
    logger.addHandler(h3)

    return logger

def main():
    status = ""
    result = Result.OK
    result_error = Result.UNKNOWN

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
            sys.exit(Result.UNKNOWN.value)

        # Validity check for input parameters
        if interface == "" or address == "":
            mylogger.error(f"Invalid interface address '{ifaddress}'")
            sys.exit(Result.UNKNOWN.value)
        if not re.match(r"^[a-z0-9]+$", interface):
            mylogger.error(f"Invalid interface '{interface}'")
            sys.exit(Result.UNKNOWN.value)
        if not re.match(r"^-?[a-f0-9.:]+$", address):
            mylogger.error(f"Invalid address '{address}'")
            sys.exit(Result.UNKNOWN.value)

        # Negate address by prepending "-"
        negate = False
        if address.startswith("-"):
            address = address[1:]
            negate = True

        # Warning or critical?
        if result_error != Result.CRITICAL:
            if args.warninglist and interface in args.warninglist:
                result_error = Result.WARNING
            elif args.criticallist and interface in args.criticallist:
                result_error = Result.CRITICAL
            else:
                result_error = Result.CRITICAL

        # Run 'ip -o address show <interface>'
        try:
            cmd_df = ["ip", "-o", "address", "show", interface]
            mylogger.debug(f'Running OS command line: {cmd_df}')
            process = run(cmd_df, check=True, timeout=10, stdout=PIPE)
        except (OSError, TimeoutExpired, ValueError) as e:
            mylogger.debug(f'{e}')
            sys.exit(Result.UNKNOWN.value)
        except Exception as e:
            mylogger.debug(f'Unexpected exception: {e}')
            sys.exit(Result.UNKNOWN.value)

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

    # Print status and exit with Nagios result
    msg = f"{result.name} - {status}"
    print(msg)
    mylogger.debug(msg)
    sys.exit(result.value)

if __name__ == "__main__":
    main()
