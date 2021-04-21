from scapy.all import *
from scapy.layers.http import HTTPRequest  # import HTTP packet
from colorama import init, Fore

# initialize colorama
init()
# define colors
GREEN = Fore.GREEN
RED   = Fore.RED
RESET = Fore.RESET


def sniff_packets(iface=None):
    """
    Sniff 80 port packets with `iface`, if None (default), then the
    Scapy's default interface is used
    """
    if iface:
        # port 80 for http (generally)
        # `process_packet` is the callback
        sniff(filter="port 80", prn=process_packet, iface=iface, store=False)
    else:
        # sniff with default interface
        sniff(filter="port 80", prn=process_packet, store=False)

def process_packet(packet):
    """
    This function is executed whenever a packet is sniffed
    """
    if packet.haslayer(HTTPRequest):
        # if this packet is an HTTP Request
        # get the requested URL
        url = packet[HTTPRequest].Host.decode() + packet[HTTPRequest].Path.decode()
        # get the requester's IP Address
        ip = packet[IP].src
        # get the request method
        method = packet[HTTPRequest].Method.decode()
        print(f"\n{GREEN}[+] {ip} Requested {url} with {method}{RESET}")
        if show_raw and packet.haslayer(Raw) and method == "POST":
            # if show_raw flag is enabled, has raw data, and the requested method is "POST"
            # then show raw
            print(f"\n{RED}[*] Some useful Raw data: {packet[Raw].load}{RESET}")

        # Check Vulnerabilties
        check_vulns(url, ip)

def check_vulns(query, ip):
    if detect_sqli(query):
        print(f"\n{RED}SQLi detected:{RESET} {query} {ip}")
    if detect_xss(query):
        print(f"\n{RED}XSS detected:{RESET} {query} {ip}")

def detect_sqli(query):
    #Clear Text SQL injection test, will create false positives. 
    regex=re.compile('drop|delete|truncate|update|insert|select|declare|union|create|concat', re.IGNORECASE)
    if regex.search(query):
        return True

    #look for single quote, = and --
    regex=re.compile('((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))|\w*((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))', re.IGNORECASE)
    if regex.search(query):
        return True

    #look for MSExec
    regex=re.compile('exec(\s|\+)+(s|x)p\w+', re.IGNORECASE)
    if regex.search(query):
        return True

    # hex equivalent for single quote, zero or more alphanumeric or underscore characters
    regex=re.compile('/\w*((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))/ix', re.IGNORECASE)
    if regex.search(query):
        return True

    return False


def detect_xss(query):
    # "script" and "on" alerts
    regex = re.compile('(\b)(on\S+)(\s*)=|javascript|(<\s*)(\/*)script', re.IGNORECASE)
    if regex.search(query):
        return True
    
    # Simple XSS attacks
    regex = re.compile('((\%3C)|<)((\%2F)|\/)*[a-z0-9\%]+((\%3E)|>)')
    if regex.search(query):
        return True


    # XSS for "<img src" attack
    regex = re.compile('((\%3C)|<)((\%69)|i|(\%49))((\%6D)|m|(\%4D))((\%67)|g|(\%47))[^\n]+((\%3E)|>)')
    if regex.search(query):
        return True

    # XSS with anything with "<" or ">". Paranoid XSS detection
    regex = re.compile('((\%3C)|<)[^\n]+((\%3E)|>)')
    if regex.search(query):
        return True

    return False


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="HTTP Packet Sniffer, this is useful when you're a man in the middle." \
                                                 + "It is suggested that you run arp spoof before you use this script, otherwise it'll sniff your personal packets")
    parser.add_argument("-i", "--iface", help="Interface to use, default is scapy's default interface")
    parser.add_argument("--show-raw", dest="show_raw", action="store_true", help="Whether to print POST raw data, such as passwords, search queries, etc.")
    # parse arguments
    args = parser.parse_args()
    iface = args.iface
    show_raw = args.show_raw
    sniff_packets(iface)
