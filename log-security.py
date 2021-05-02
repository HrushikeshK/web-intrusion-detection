from apachelogs import LogParser
import re
import sys
from colorama import init, Fore

# initialize colorama
init()
# define colors
GREEN = Fore.GREEN
RED   = Fore.RED
RESET = Fore.RESET



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

def check_vulns(query, ip):
    if detect_sqli(query):
        print(f"\n{RED}SQLi detected:{RESET} {query} {ip}")
    if detect_xss(query):
        print(f"\n{RED}XSS detected:{RESET} {query} {ip}")


parser = LogParser("%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\"")

with open('apache_logs') as fp:
    for entry in parser.parse_lines(fp, ignore_invalid=True):
        try:
            query = entry.request_line.split(" ")[1] 
            ip = entry.remote_host
            check_vulns(query, ip)
        except:
            print("Exception: ", sys.exc_info()[0])