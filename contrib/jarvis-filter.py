import re
import socket
import json
import time
import threading
import collections
import mitmproxy.http
import mitmproxy.websocket

from mitmproxy import ctx
from bs4 import BeautifulSoup
from watchdog.observers import Observer
from watchdog.events import PatternMatchingEventHandler
from urllib.parse import urlparse
from urllib.parse import urljoin

from wsproto.frame_protocol import Opcode


class JarvisFilter:

    def __init__(self):
        self.allowedHosts = set()
        self.discoveredPageHosts = set()
        self.last100Hosts = collections.deque(maxlen=100)
        self.firstRun = True
        self.lock = threading.Lock()
            
        self.loadFile("C:\\Users\\ben-local\\Code\\mitmproxy\\contrib\\filter\\hosts.json")
        
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
        self.allowedHosts = set()
        with self.lock:
            with open(srcPath) as f:
                data = json.load(f)
                self.allowedHosts.update(data['hosts'])
            print(self.allowedHosts)


    def isHostNameBlocked(self, hostname):
        for host in self.allowedHosts:
            if host in hostname:
                return False
        return True


    def processTagSrc(self, tag, parsedUri):
        src = tag['src']
        if "://" not in src:
            self.last100Hosts.append(parsedUri.hostname)
        else:  
            parsed = urlparse(src)
            self.last100Hosts.append(parsed.hostname)
        self.discoveredPageHosts = set(self.last100Hosts)
        ctx.log.info("Currently caching " + str(len(self.discoveredPageHosts)) + " hosts")
        

    def response(self, flow: mitmproxy.http.HTTPFlow):
        ctx.log.info("Content type is " + flow.response.headers.get("Content-Type", "null") + " for url: " + flow.request.pretty_url)
        parsedUri = urlparse(flow.request.pretty_url)

        if self.isHostNameBlocked(parsedUri.hostname) and parsedUri.hostname not in self.discoveredPageHosts:
            # if the request url is not in allowed hosts or discovered hosts from an allowed host, strip out all images and video
            # from html, and if this request object was from some AJAX and fetching media directly, simply return empty response
            contentType = flow.response.headers.get("Content-Type", "").lower()
            if 'text/html' in contentType:
                if not flow.response.text:
                    ctx.log.info("No text received")
                    ctx.log.info("Got headers: " + str(flow.response.headers))
                else:
                    ctx.log.info("HTML detected, parsing page: " + flow.request.pretty_url)

                    # remove data:image/ urls if present - Google includes in the initial response
                    # original: 'data:image/.*?base64,[A-Za-z0-9+/]+'
                    p = re.compile(r'data:image[A-Za-z0-9+/,\\;]+')
                    doc = p.sub('', flow.response.text)
                    soup = BeautifulSoup(doc, 'html.parser')

                    for img in soup.find_all('img'):
                        del img['src']

                    for vid in soup.find_all('video'):
                        del vid['src']

                    flow.response.text = soup.prettify()
            elif 'image' in contentType:
                ctx.log.info("Image detected, returning empty response body")
                flow.response.text = ""
            elif 'video' in contentType:
                ctx.log.info("Video detected, returning empty response body")
                flow.response.text = ""
            elif 'javascript' in contentType:
                p = re.compile(r'data:image[A-Za-z0-9+/,\\;]+')
                flow.response.text = p.sub('', flow.response.text)
        else:
            # here we whitelist all found links on a page whose host is already whitelisted
            if 'text/html' in flow.response.headers.get("Content-Type", "").lower():
                ctx.log.info("HTML detected, parsing page: " + flow.request.pretty_url)
                soup = BeautifulSoup(flow.response.text, 'html.parser')

                for img in soup.find_all('img'):
                    self.processTagSrc(img, parsedUri)

                for vid in soup.find_all('video'):
                    self.processTagSrc(vid, parsedUri)
                    
                ctx.log.info("Added dynamically discovered hosts from whitelisted page: " + str(self.discoveredPageHosts))


    def websocket_message(self, flow: mitmproxy.websocket.WebSocketFlow):
        """
            Called when a WebSocket message is received from the client or
            server. The most recent message will be flow.messages[-1]. The
            message is user-modifiable. Currently there are two types of
            messages, corresponding to the BINARY and TEXT frame types.
        """
        if flow.server_conn.address[0] not in self.allowedHosts:
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