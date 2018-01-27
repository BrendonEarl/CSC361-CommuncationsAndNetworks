import sys
import ssl
import socket
from urllib.parse import urlparse


class SmartWebClient():
    def __init__(self, url):
        self.sock = None
        self.protocol = None
        self.cookies = []

        try:
            self.url = urlparse("https://{}".format(url))
        except ValueError:
            print("!! Malformed URL entered")
            print("Please re-run me to try again")
            return

        print('\n.............................')
        print('..Starting Smart Web Client..')
        print('.............................\n')

        print("---\\/ Finding available HTTP scheme and snatching cookies  \\/ ---\n")
        self.findHttpScheme()

        print("\n---\\/ Testing for HTTP/2 availability \\/---\n")
        self.testHttp2()

        print("\n\n---\\/ Solution \\/---\n")
        self.reportSoln()

        print()
        self.closeHttpSocket(self.sock)

    def reportSoln(self):
        print("website: {}".format(self.url.netloc))
        print("1. Support of HTTPS: {}".format(
            "yes" if self.url.scheme == 'https' else "no"))
        print("2. The newest HTTP versions that the server supports: {}".format(
            self.protocol))
        print("3. List of Cookies:")
        if self.cookies is not None:
            for cookie in self.cookies:
                print("name: -, key: {}{}".format(
                    cookie['key'],
                    ", domain-name: {}".format(cookie['domain']
                                               if cookie['domain'] is not None else "")
                ))

    def findHttpScheme(self):
        self.sock = self.openHttpSocket(self.url)
        self.httpSend("HEAD", self.url, 'HTTP/1.1')

        header, body = self.parseResponse(self.httpRecv())
        if header is None:
            return None

        if header['status-code'] == 505:
            self.protocol = header['http-version']
        elif header['status-code'] == 302 or header['status-code'] == 301:
            self.protocol = header['http-version']
            self.closeHttpSocket(self.sock)

            if 'location' in header:
                self.url = urlparse(header['location'])
            if self.url.scheme == '':
                self.url.scheme = 'http'

            self.findHttpScheme()
        elif header['status-code'] == 200:
            self.protocol = 'HTTP/1.1'
        else:
            print("Unexpected server error: {}".format(header['status-code']))

        return header

    def testHttp2(self):
        self.closeHttpSocket(self.sock)
        self.sock = self.openHttpSocket(self.url, True)

        if (self.url.scheme == 'https' and (
            self.sock.selected_alpn_protocol() == 'h2' or
            self.sock.selected_npn_protocol() == 'h2'
        )):
            self.protocol = 'HTTP/2'

    def httpSend(self, method, parsedURL, httpV):
        if self.sock is not None:
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
        if self.sock is not None:
            try:
                resp = self.sock.recv().decode()
            except TypeError:
                print('!! Empty response')
                return None
            except ConnectionResetError:
                print('!! Connection dropped by peer')
                return None

            splitResp = resp.split("\r\n\r\n")

            print("\n-Response header-")
            print(splitResp[0])

            if len(splitResp) > 1:
                print("\n-Response body-")
                print(splitResp[1])

            return resp
        else:
            print("No Socket Initialized")
            return None

    def parseResponse(self, resp):
        parsedResponse = {}

        try:
            splitResp = resp.split("\r\n\r\n")
        except AttributeError:
            print('!! No response to parse')
            return (None, None)

        header = splitResp[0]
        if len(splitResp) > 1:
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
            if splitAttribute[0].lower() != 'set-cookie':
                try:
                    parsedResponse.update({
                        splitAttribute[0].lower(): splitAttribute[1]
                    })
                except IndexError:
                    print('!! Malformed header attribute: {}'.format(splitAttribute))
            else:
                crumbs = splitAttribute[1].split("; ")

                key = crumbs[0].split('=')[0]
                domain = None

                for crumb in crumbs:
                    if 'domain' in crumb:
                        try:
                            domain = crumb.split('=')[1]
                        except IndexError:
                            print('!! Malformed header domain cookie: {}'.format(
                                splitAttribute
                            ))

                cookie = {
                    'key': key,
                    'domain': domain
                }

                self.cookies.append(cookie)
        return (parsedResponse, body)

    def openHttpSocket(self, parsedURL, h2=False):
        SCHEME = "HTTPS" if parsedURL.scheme == 'https' else "HTTP"
        PORT = 443 if parsedURL.scheme == 'https' else 80
        PROTOCOLS = ['h2', 'http/1.1'] if h2 else ['http/1.1']

        print("-Opening {} Socket on Port {}-".format(SCHEME, PORT))

        if SCHEME == 'HTTPS':
            ctx = ssl.create_default_context()
            ctx.set_alpn_protocols(PROTOCOLS)
            ctx.set_npn_protocols(PROTOCOLS)

            sock = ctx.wrap_socket(
                socket.socket(socket.AF_INET, socket.SOCK_STREAM), server_hostname=parsedURL.netloc
            )
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        try:
            sock.connect((parsedURL.netloc, PORT))
        except (ssl.SSLError, ssl.CertificateError):
            print('!! SSL Certificate Vification Failed')
            self.closeHttpSocket(sock)
            self.url = parsedURL._replace(scheme="http")
            return self.openHttpSocket(self.url)
        return sock

    def closeHttpSocket(self, sock):
        if sock is not None:
            sock.close()
            print("-Socket Closed-")
        else:
            print("No Socket To Close")


if __name__ == "__main__":
    try:
        if sys.argv[1] is None:
            print("No URL provided")
        else:
            SmartWebClient(sys.argv[1])
    except:
        print("!! Uh Oh! Something unexpected happened:")
        e = sys.exc_info()[0]
        print(e)
        # raise e
