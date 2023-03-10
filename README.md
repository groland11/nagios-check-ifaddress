![last commit](https://img.shields.io/github/last-commit/groland11/nagios-check-ifaddress.svg)
![release date](https://img.shields.io/github/release-date/groland11/nagios-check-ifaddress.svg)
![languages](https://img.shields.io/github/languages/top/groland11/nagios-check-ifaddress.svg)
![license](https://img.shields.io/github/license/groland11/nagios-check-ifaddress.svg)

# nagios-check-ifaddress
Nagios check for IP addresses on local network interfaces
- Include and / or exclude IP addresses for local network interfaces
- Especially usefull if you want to check floating / virtual IP addresses in a cluster / high availability environment
- Exclude certain IP addresses to detect split brain situations in clusters
- Chose between critical or warning check result for specific interfaces
- Log only verbose/debug ouitput to logfile. Regular Nagios output message will still be printed to stdout. This way you can enable verbose output, while the Nagios check keeps running.

## Requirements
- Red Hat Enterprise Linux 7/8/9 or similar; probably works on most Linux distributions
- Python >= 3.6

## Usage
```
./check-ifaddress.py -h
usage: check-ifaddress.py [-h] -a IFADDRESSES [IFADDRESSES ...] [-w WARNINGLIST] [-c CRITICALLIST] [-v] [--logfile LOGFILE]

Check network interface IP addresses

Options:
  -h, --help            show this help message and exit
  -a IFADDRESSES [IFADDRESSES ...], --address IFADDRESSES [IFADDRESSES ...]
                        network interface name and IP address, e.g. "enp1s0/192.168.0.10"
  -w [WARNINGLIST], --warning [WARNINGLIST]
                        list of network interface which only generate warnings, e.g. "enp2s0,enp7s0"
  -c [CRITICALLIST], --critical [CRITICALLIST]
                        list of network interfaces which always generate critical errors, e.g. "enp3s0,enp4s0"
  -v, --verbose         enable verbose output
  --logfile LOGFILE     log verbose output do logfile, default: <stdout>

```

## Example
IP address 192.168.122.102 must be assigned to network interface enp1s0, but not 192.168.122.100.
If 192.168.122.100 is a virtual IP address in a network cluster, and the check fails on one of the nodes, you know that this node is in a failover state.
```
# ./check-ifaddress.py -a enp1s0/192.168.122.102 enp1s0/-192.168.122.100 
OK - enp1s0/192.168.122.102;enp1s0/-192.168.122.100;
```


