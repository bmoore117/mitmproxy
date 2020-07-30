import re
import socket
import json
import time
import threading
import collections
import mitmproxy.http
import mitmproxy.websocket

from mitmproxy import ctx
from mitmproxy import http
from bs4 import BeautifulSoup
from watchdog.observers import Observer
from watchdog.events import PatternMatchingEventHandler
from urllib.parse import urlparse
from urllib.parse import urljoin

from wsproto.frame_protocol import Opcode


class JarvisFilter:

    def __init__(self):
        self.allowedUrlPaths = set() # these are manually added by users
        self.discoveredPageUrlPaths = set() # these are dyamically discovered from pages users visit
        self.last100UrlPaths = collections.deque(maxlen=100)
        self.firstRun = True
        self.lock = threading.Lock()
            
        self.loadFile("C:\\Users\\ben-local\\Code\\mitmproxy\\contrib\\filter\\hosts.json")
        
        # remove data:image/ urls if present - Google includes in the initial response
        # original: 'data:image/.*?base64,[A-Za-z0-9+/]+'
        self.dataUrlRegex = re.compile(r'data:image[A-Za-z0-9+/,\\;=]+')
        
        patterns = "*.json"
        ignore_patterns = ""
        ignore_directories = True
        case_sensitive = True
        handler = PatternMatchingEventHandler(patterns, ignore_patterns, ignore_directories, case_sensitive)
        handler.on_modified = self.on_modified

        path = "C:\\Users\\ben-local\\Code\\mitmproxy\\contrib\\filter"
        observer = Observer()
        observer.schedule(handler, path, recursive=False)
        observer.start()


    def on_modified(self, event):
        self.loadFile(event.src_path)


    def loadFile(self, srcPath):
        self.allowedUrlPaths = set()
        with self.lock:
            with open(srcPath) as f:
                data = json.load(f)
                self.allowedUrlPaths.update(data['hosts'])
            print(self.allowedUrlPaths)


    def isUrlPathBlocked(self, url):
        # /images/dogs in /images/dogs/pugs,
        # /images/dogs not in /images/cats, -> /images/dogs = urlPath, /images/cats = url
        for urlPath in self.discoveredPageUrlPaths:
            if urlPath in url:
                return False # not blocked
        
        for urlPath in self.allowedUrlPaths:
            if urlPath in url:
                return False # not blocked
        
        return True # blocked
        

    def getUrlDirPath(self, parsedUri):
        lastIndexOfSlash = parsedUri.path.rindex("/") + 1
        dirPath = parsedUri.path[:lastIndexOfSlash]
        return parsedUri.hostname + dirPath

    def processSrc(self, src, currentPageUri):
        parsed = None
        if "://" not in src:
            if src.startswith("//"):
                fullUrl = currentPageUri.scheme + ":" + src
            elif src.startswith("/"):
                fullUrl = currentPageUri.scheme + ":/" + src    
            else:
                fullUrl = currentPageUri.scheme + "://" + src
            parsed = urlparse(fullUrl)
        else:  
            parsed = urlparse(src)
        
        self.last100UrlPaths.append(self.getUrlDirPath(parsed))

    def processTagSrc(self, tag, currentPageUri):
        if (tag.has_attr('src')):
            self.processSrc(tag['src'], currentPageUri)
        if (tag.has_attr('data-src')):
            self.processSrc(tag['data-src'], currentPageUri)
            
        self.discoveredPageUrlPaths = set(self.last100UrlPaths)        


    def response(self, flow: mitmproxy.http.HTTPFlow):
        ctx.log.info("Content type is " + flow.response.headers.get("Content-Type", "null") + " for url: " + flow.request.pretty_url)
        
        parsedUri = urlparse(flow.request.pretty_url)
        url = self.getUrlDirPath(parsedUri)
        
        ctx.log.info("Constructed url is " + url)

        if self.isUrlPathBlocked(url):
            # if the request url is not in allowed hosts or discovered hosts from an allowed host, strip out data:image urls
            # from html, and if this request object was from some AJAX and fetching media directly, return 404s
            contentType = flow.response.headers.get("Content-Type", "").lower()
            if 'text/html' in contentType:
                try:
                    if not flow.response.text: # this line may fail due to WOFF responses, it has been observed in the wild
                        ctx.log.info("No text received")
                        ctx.log.info("Got headers: " + str(flow.response.headers))
                    else:
                        ctx.log.info("HTML detected, parsing page: " + flow.request.pretty_url)

                        doc = self.dataUrlRegex.sub('', flow.response.text)
                        soup = BeautifulSoup(doc, 'html.parser')

                        flow.response.text = soup.prettify()
                except ValueError:
                    ctx.log.info("Received message with undecipherable encoding, forwarding as-is")
            elif 'image' in contentType:
                ctx.log.info("Image detected, returning empty response body")
                flow.response = http.HTTPResponse.make(404)
            elif 'video' in contentType:
                ctx.log.info("Video detected, returning empty response body")
                flow.response = http.HTTPResponse.make(404)
            elif 'javascript' in contentType:
                flow.response.text = self.dataUrlRegex.sub('', flow.response.text)
        else:
            # here we whitelist all found links on a page whose host is already whitelisted
            if 'text/html' in flow.response.headers.get("Content-Type", "").lower():
                ctx.log.info("HTML detected, parsing page: " + flow.request.pretty_url)
                try:
                    soup = BeautifulSoup(flow.response.text, 'html.parser') # this line may fail due to encoding, unlikely but..

                    for img in soup.find_all('img'):
                        self.processTagSrc(img, parsedUri)

                    for vid in soup.find_all('video'):
                        self.processTagSrc(vid, parsedUri)
                    
                    ctx.log.info("Added dynamically discovered hosts from whitelisted page: " + str(self.discoveredPageUrlPaths))
                except ValueError:
                    ctx.log.info("Unable to dynamically discover hosts as content encoding was undecipherable")


    def websocket_message(self, flow: mitmproxy.websocket.WebSocketFlow):
        """
            Called when a WebSocket message is received from the client or
            server. The most recent message will be flow.messages[-1]. The
            message is user-modifiable. Currently there are two types of
            messages, corresponding to the BINARY and TEXT frame types.
        """
        if flow.server_conn.address[0] not in self.allowedUrlPaths:
            if flow.messages[-1].type == Opcode.BINARY:
                ctx.log.info("Blocking binary frame type")
                flow.messages[-1].content = ""


    def getHostNameForIp(self, ip):
        result = socket.gethostbyaddr(ip)
        return result[0]


    def get_ips_by_dns_lookup(self, target, port=None):
    #    this function takes the passed target and optional port and does a dns
    #    lookup. it returns the ips that it finds to the caller.
    #    :param target:  the URI that you'd like to get the ip address(es) for
    #    :type target:   string
    #    :param port:    which port do you want to do the lookup against?
    #    :type port:     integer
    #    :returns ips:   all of the discovered ips for the target
    #    :rtype ips:     list of strings
        if not port:
            port = 80

        return list(map(lambda x: x[4][0], socket.getaddrinfo('{}.'.format(target),port,type=socket.SOCK_STREAM)))


addons = [
    JarvisFilter()
]