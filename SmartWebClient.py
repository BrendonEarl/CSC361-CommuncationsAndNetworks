import sys
import socket
from urllib.parse import urlparse, urlunparse

class SmartWebClient():
    def  __init__(self, parsedURI = {}):
        url = urlunparse(parsedURI)
        sys.stdout.write('Starting Smart Web Client\n\n')
        # open server socket
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((uri, 80))
        self.findHttpScheme(uri)

    def findHttpScheme(self, uri):
        print("-----Finding available HTTP scheme---")
        self.httpSend("HEAD", uri, 'HTTP/1.1')
        resp = self.httpRecv()
    
    def findHttpProtocol(sef, uri)

    def httpSend(self, method, uri, httpV,):
        print("---Request begin---")

        req = "{0} {1} {2}\r\n\r\n".format(method, uri, httpV)
        print(req.strip())
        print("Host: {0}".format(uri))
        print("Connection: Keep-Alive")
        self.sock.send(req.encode())

        print("\n---Request end---")
        print("HTTP request sent, awaiting response...")
        
    def httpRecv(self):
        data = self.sock.recv(1024).decode().split("\r\n\r\n")
        print("\n---Response header---")
        print(data[0])
        if (len(data) > 1):
            print("\n---Response body---")
            print(data[1])
        return(data)


if __name__ == "__main__":
    try:
        # TODO: Add proper error handling of bad URIs
        parsedURI = urlparse(sys.argv[1])
        SmartWebClient(parsedURI)
    except ValueError:
        sys.stderr.write('Incorrect URI format. Try again')
    