from apachelogs import LogParser
import re
import sys

parser = LogParser("%h %l %u %t \"%r\" %>s %b \"%{Referer}i\" \"%{User-Agent}i\"")

with open('apache_logs') as fp:
    for entry in parser.parse_lines(fp, ignore_invalid=True):
        try:
            print(str(entry.request_time),  entry.request_line.split(" ")[1])
        except:
            print("Exception: ", sys.exc_info()[0])


def detect_sqli(payload):

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


def detect_xss(payload):
    pass

def detect_rce(payload):
    pass

