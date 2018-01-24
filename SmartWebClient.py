import sys
import socket
from urllib.parse import urlparse, urlunparse

class SmartWebClient():
    def  __init__(self, url):
        self.sock = None
        self.protocol = None
        self.url = urlparse("//{}".format(url))

        print('Starting Smart Web Client\n')
        print('Looking for URL scheme\n')
        self.findHttpScheme(parsedURL)
        self.findHttpProtocol(parsedURL)


    def findHttpScheme(self, parsedURL):
        print("-----Finding available HTTP scheme---")
        self.openHttpSocket(parsedURL.netloc, False)
        self.httpSend("HEAD", parsedURL.path, 'HTTP/1.1', parsedURL.netloc)
        resp = self.httpRecv()
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
        httpV, status, reason = splitHeader[0].split(' ')
        parsedResponse.update({
            "HTTP-Version": httpV,
            "Status-Code": int(status),
            "Reason-Phrase": reason
        })
        for attribute in splitHeader[1:]:
            splitAttribute = attribute.split(": ")
            parsedResponse.update({
                splitAttribute[0]: splitAttribute[1]
            })
        return (parsedResponse, body)        


    def openHttpSocket(self, uri, secure = False):
        print("---Opening {} Socket on Port {}".format("HTTPS" if secure else "HTTP", 443 if secure else 80))
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((uri, 80))
        self.scheme = "HTTP"


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
    