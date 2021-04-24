import json
import sys
import re
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

def check_vulns(url,req_data, ip):
    if detect_sqli(url) or detect_sqli(req_data):
        print(f"\n{RED}SQLi detected:{RESET} {ip} {url} {req_data}")
    if detect_xss(url) or detect_xss(req_data):
        print(f"\n{RED}XSS detected:{RESET} {ip} {url} {req_data}")

def get_data(lines):
    data = {}
    for line in range(len(lines)):
        if lines[line] == '': continue
        if lines[line].startswith('--'):
            [id, part] = [x for x in lines[line].split('-') if x != '']
            # Get Source IP
            if part == 'A':
                data[id] = {}
                ip = re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", lines[line+1])
                if len(ip) != 0:
                    data[id]['ip'] = ip[0]
                continue
            # Get Method and URL
            if part == 'B':
                method = lines[line+1].split(' ')[0]
                url = lines[line+1].split(' ')[1]
                data[id]['method'] = method
                data[id]['url'] = url
                continue
            # Get Request Data
            if part == 'C':
                req_data = ''
                for x in range(line+1, len(lines)):
                    if lines[x].startswith('--'):
                        break
                    req_data += lines[x]
                data[id]['req_data'] = req_data
    return data
                    

def main():
    f = open(sys.argv[1], 'r')
    log = f.read()
    f.close()

    lines = log.splitlines()

    data = {}
    data = get_data(lines)
    
    # Parse and send to check vuln
    for id in data:
        url = data[id]['url']
        ip = data[id]['ip']
        req_data = ''
    
        if 'req_data' in data[id]:
            req_data = data[id]['req_data']
        
        check_vulns(url, req_data, ip)
    
if __name__ == '__main__':
    main()
