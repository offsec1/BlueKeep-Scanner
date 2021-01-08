import argparse
import sys
from scanners.bluekeep import scan


def print_banner():
    print("""\033[34m
      ____  _            _  __               
     |  _ \| |          | |/ /               
     | |_) | |_   _  ___| ' / ___  ___ _ __  
     |  _ <| | | | |/ _ \  < / _ \/ _ \ '_ \ 
     | |_) | | |_| |  __/ . \  __/  __/ |_) |
     |____/|_|\__,_|\___|_|\_\___|\___| .__/ 
                                      | |    
                                      |_|
    \033[0m""")


# main.py
# CVE-2019-0708 "Bluekeep" Vulnerability Scanner.
#
# Usage: main.py --host [HOST]
#
# Arguments:
#   Host - IP address of the host to scan
#   -v   - Enable verbose output (optional)
#
# Confirmed Targets:
#   - Windows 7
#   - Windows Server 2008; Windows Server 2008 R2
#   - Windows Server 2003
#   - Windows XP
#
# References:
# - https://www.seebug.org/vuldb/ssvid-97954
# - https://github.com/zerosum0x0/CVE-2019-0708
# - https://github.com/fenixns/CVE-2019-0708

if __name__ == '__main__':
    # Exit on wrong usage
    if len(sys.argv) != 3:
        print("Usage: python3 main.py --host 127.0.0.1")
        sys.exit()

    print_banner()
    # Parse arguments
    parser = argparse.ArgumentParser(epilog='\tExample: \r\npython ' + sys.argv[0] + " [options]")
    parser.add_argument('--host', help="target ip to scan for CVE-2019-0708 - BlueKeep")
    opts = parser.parse_args()
    scan(opts.host, "")  # We could add verbosity level as second parameter
