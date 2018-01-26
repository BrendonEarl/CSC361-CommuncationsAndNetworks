import sys
import ssl
import socket
from urllib.parse import urlparse, urlunparse

class SmartWebClient():
    def  __init__(self, url):
        self.sock = None
        self.protocol = None
        self.url = urlparse("//{}".format(url))

        print('Starting Smart Web Client\n')
        print('Looking for URL scheme\n')
        self.findHttpScheme(self.url)
        self.findHttpProtocol(self.url)


    def reportSoln(self):
        print("website: {}".format(self.url.netloc))
        print("1. Support of HTTPS: {}".format("yes" if self.url.scheme == 'https' else "no"))
        print("2. The newest HTTP versions that the server supports: {}".format(self.protocol))
        print("3. List of Cookies:")
        if self.cookies != None:
            for cookie in self.cookies:
                print("name: {}, key: {}, domain name: {}".format(cookie.name, cookie.key, cookie.domain))


    def findHttpScheme(self):
        print("-----Finding available HTTP scheme---")
        self.openHttpSocket(parsedURL)
        self.httpSend("HEAD", parsedURL.path, 'HTTP/1.1', parsedURL.netloc)
        resp = self.httpRecv()
        if(resp[0]['Status-Code'] == 302):
            print('here')
            self.url = urlparse(resp[0]['Location'])
            if (self.url.scheme == None): self.url.scheme = 'http'
            self.openHttpSocket(parsedURL)
        self.scheme = 'HTTP'


    def findHttpProtocol(self, parsedURL):
        print("-----Finding available HTTP protocol---")
        self.httpSend("HEAD", parsedURL.path, 'HTTP/1.1', parsedURL.netloc)
        resp = self.httpRecv()
        if (resp[0]['Status-Code'] == 200):
            self.protocol = 'HTTP/1.1'


    def httpSend(self, method, path, httpV, host):
        if (self.sock != None):
            print("---Request begin---")

            req = "{} {} {}\r\nHost: {}\r\nConnection: Keep-Alive\r\n\r\n".format(method, path if path != '' else "/", httpV, host)
            print(req.strip())
            self.sock.send(req.encode())

            print("\n---Request end---")
            print("HTTP request sent, awaiting response...")
        else:
            print("No Socket Initialized")


    def httpRecv(self):
        if (self.sock != None):
            resp = self.sock.recv(1024).decode()
            splitResp = resp.split("\r\n\r\n")
            print("\n---Response header---")
            print(splitResp[0])
            if (len(splitResp) > 1):
                print("\n---Response body---")
                print(splitResp[1])
            return(self.parseResponse(resp))
        else:
            print("No Socket Initialized")
            return None


    def parseResponse(self, resp):
        parsedResponse = {}
        header, body = resp.split("\r\n\r\n")
        splitHeader = header.split('\r\n')
        statusTokens = splitHeader[0].split(' ')
        parsedResponse.update({
            "HTTP-Version": statusTokens[0],
            "Status-Code": int(statusTokens[1]),
            "Reason-Phrase": ''.join("{} ".format(token) for token in statusTokens[2:])
        })
        for attribute in splitHeader[1:]:
            splitAttribute = attribute.split(": ")
            parsedResponse.update({
                splitAttribute[0]: splitAttribute[1]
            })
        return (parsedResponse, body)        


    def openHttpSocket(self, parsedURL):
        SCHEME = "HTTPS" if parsedURL.scheme == 'https' else "HTTP"
        PORT = 443 if parsedURL.scheme == 'https' else 80
        print("---Opening {} Socket on Port {}".format(SCHEME, PORT))

        if (SCHEME == 'HTTPS'):
            ctx = ssl.create_default_context()
            ctx.set_alpn_protocols(['h2', 'spdy/3', 'http/1.1'])
            self.sock = ctx.wrap_socket(
                socket.socket(socket.AF_INET, socket.SOCK_STREAM), server_hostname=parsedURL.netloc
            )
        else:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        self.sock.connect((parsedURL.netloc, PORT))


    def closeHttpSocket(self):
        if (self.sock != None):
            sock.close()
            print("---Socket Closed---")
        else:
            print("No Socket To Close")


if __name__ == "__main__":
    try:
        if (sys.argv[1] == None):
            print("No URL provided")
        else:
            SmartWebClient(sys.argv[1])
    except ValueError as ve:
        print(ve)
        sys.stderr.write('Incorrect URN format. Try again')
    