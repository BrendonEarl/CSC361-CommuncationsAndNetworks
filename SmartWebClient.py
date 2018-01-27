import sys
import ssl
import socket
from urllib.parse import urlparse, urlunparse

class SmartWebClient():
    def  __init__(self, url):
        self.sock = None
        self.protocol = None
        self.cookies = []
        self.url = urlparse("https://{}".format(url))

        print('\n.............................')
        print('..Starting Smart Web Client..')
        print('.............................\n')
        print("---\/ Finding available HTTP scheme and snatching cookies  \/ ---\n")
        resp = self.findHttpScheme()
        print("\n---\/ Testing for HTTP/2 availability \/---\n")
        self.testHttp2()
        print("\n\n---\/ Solution \/---\n")
        self.reportSoln(resp)


    def reportSoln(self, resp):
        print("website: {}".format(self.url.netloc))
        print("1. Support of HTTPS: {}".format("yes" if self.url.scheme == 'https' else "no"))
        print("2. The newest HTTP versions that the server supports: {}".format(self.protocol))
        print("3. List of Cookies:")
        if self.cookies != None:
            for cookie in self.cookies:
            # for cookie in [dict(cookies) for cookies in set([tuple(cookie.items()) for cookie in self.cookies])]:
                print("name: {}, key: {}{}".format(
                    cookie['name'],
                    cookie['key'],
                    ", domain name: {}".format(cookie['domain']) if cookie['domain'] != None else ""
                ))


    def findHttpScheme(self):
        self.sock = self.openHttpSocket(self.url)

        self.httpSend("HEAD", self.url, 'HTTP/1.1')
        header, body = self.parseResponse(self.httpRecv())
        
        if(header['status-code'] == 505):
            self.protocol = header['http-version']
        elif(header['status-code'] == 302 or header['status-code'] == 301):
            self.closeHttpSocket(self.sock)
            if 'location' in header:
                self.url = urlparse(header['location'])
            if (self.url.scheme == ''): self.url.scheme = 'http'
            self.findHttpScheme()
        else:
            self.protocol = 'HTTP/1.1'
        
        return header


    def testHttp2(self):
        self.closeHttpSocket(self.sock)
        self.sock = self.openHttpSocket(self.url, True)
        if(self.url.scheme == 'https' and \
            (self.sock.selected_alpn_protocol() == 'h2' or self.sock.selected_npn_protocol() == 'h2') or \
            (self.sock.selected_alpn_protocol() == 'h2c' or self.sock.selected_npn_protocol() == 'h2c')
            ):
                self.protocol = 'HTTP/2'


    def httpSend(self, method, parsedURL, httpV):
        if (self.sock != None):
            print("-Request begin-")

            req = "{} {} {}\r\nhost: {}\r\nconnection: {}\r\n\r\n".format(
                method,
                parsedURL.path if parsedURL.path != '' else "/",
                httpV,
                parsedURL.netloc,
                "keep-alive"
            )

            print(req.strip())
            self.sock.send(req.encode())

            print("\n-Request end-")
            print("HTTP request sent, awaiting response...")
        else:
            print("No Socket Initialized")


    def httpRecv(self):
        if (self.sock != None):
            resp = self.sock.recv().decode()
            splitResp = resp.split("\r\n\r\n")

            print("\n-Response header-")
            print(splitResp[0])

            if (len(splitResp) > 1):
                print("\n-Response body-")
                print(splitResp[1])

            return resp
        else:
            print("No Socket Initialized")
            return None


    def parseResponse(self, resp):
        parsedResponse = {}

        splitResp = resp.split("\r\n\r\n")
        header = splitResp[0]
        if (len(splitResp) > 1):
            body = splitResp[1]
        else:
            body = None

        splitHeader = header.split('\r\n')
        statusTokens = splitHeader[0].split(' ')

        parsedResponse.update({
            "http-version": statusTokens[0],
            "status-code": int(statusTokens[1]),
            "reason-phrase": ''.join("{} ".format(token) for token in statusTokens[2:])
        })

        for attribute in splitHeader[1:]:
            splitAttribute = attribute.split(": ")
            if(splitAttribute[0].lower() != 'set-cookie'):
                try:
                    parsedResponse.update({
                        splitAttribute[0].lower(): splitAttribute[1]
                    })
                except IndexError:
                    print('Malformed header attribute: {}'.format(splitAttribute))
            else:
                crumbs = splitAttribute[1].split("; ")

                name = crumbs[0].split('=')[0]
                key = crumbs[0][len(name)+1:]
                domain = None

                for crumb in crumbs:
                    if ('domain' in crumb):
                        domain = crumb.split('=')[1]

                cookie = {
                    'name': name,
                    'key': key,
                    'domain': domain
                }

                self.cookies.append(cookie)
        return (parsedResponse, body)        


    def openHttpSocket(self, parsedURL, h2 = False):
        SCHEME = "HTTPS" if parsedURL.scheme == 'https' else "HTTP"
        PORT = 443 if parsedURL.scheme == 'https' else 80
        PROTOCOLS = ['h2', 'http/1.1'] if h2 else ['http/1.1']

        print("-Opening {} Socket on Port {}-".format(SCHEME, PORT))

        if (SCHEME == 'HTTPS'):
            ctx = ssl.create_default_context()
            ctx.set_alpn_protocols(PROTOCOLS)
            ctx.set_npn_protocols(PROTOCOLS)

            sock = ctx.wrap_socket(
                socket.socket(socket.AF_INET, socket.SOCK_STREAM), server_hostname=parsedURL.netloc
            )
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        sock.connect((parsedURL.netloc, PORT))
        return sock


    def closeHttpSocket(self, sock):
        if (sock != None):
            sock.close()
            print("-Socket Closed-")
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
        raise ve
        sys.stderr.write('Incorrect URN format. Try again')
    