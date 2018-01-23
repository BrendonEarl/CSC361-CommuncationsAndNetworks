import sys
import socket
from urllib.parse import urlparse, urlunparse

class SmartWebClient():
    def  __init__(self, uri):
        self.sock = None
        self.scheme = None
        self.protocol = None

        print('Starting Smart Web Client\n')

        print('Looking for URL scheme\n')
        self.openHttpSocket(uri)
        self.findHttpProtocol(uri)


    def findHttpScheme(self, uri):
        print("-----Finding available HTTP scheme---")
        self.httpSend("HEAD", uri, 'HTTP/1.1')
        resp = self.httpRecv()
        scheme = 'http'


    def findHttpProtocol(self, uri):
        print("-----Finding available HTTP protocol---")
        self.httpSend("HEAD", uri, 'HTTP/1.1')
        resp = self.httpRecv()


    def httpSend(self, method, uri, httpV):
        if (self.sock != None):
            print("---Request begin---")

            req = "{} {} {}\r\n\r\n".format(method, uri, httpV)
            print(req.strip())
            print("Host: {}".format(uri))
            print("Connection: Keep-Alive")
            self.sock.send(req.encode())

            print("\n---Request end---")
            print("HTTP request sent, awaiting response...")
        else:
            print("No Socket Initialized")


    def httpRecv(self):
        if (self.sock != None):
            data = self.sock.recv(1024).decode().split("\r\n\r\n")
            print("\n---Response header---")
            print(data[0])
            if (len(data) > 1):
                print("\n---Response body---")
                print(data[1])
            return(data)
        else:
            print("No Socket Initialized")
            return None


    def openHttpSocket(self, uri, secure = False):
        print("---Opening {} Socket on Port {}".format("HTTPS" if secure else "HTTP", 443 if secure else 80))
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((uri, 80))

    def closeHttpSocket(self):
        if (self.sock != None):
            sock.close()
            print("---Socket Closed---")
        else:
            print("No Socket To Close")


if __name__ == "__main__":
    try:
        # TODO: Add proper error handling of bad URIs
        parsedURI = urlparse(sys.argv[1])
        SmartWebClient(sys.argv[1])
    except ValueError:
        sys.stderr.write('Incorrect URI format. Try again')
    