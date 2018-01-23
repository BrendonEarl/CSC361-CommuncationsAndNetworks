import sys
import socket
from urllib.parse import urlparse, urlunparse

class SmartWebClient():
   def  __init__(self, parsedURL = {}):
        sys.stdout.write('Starting Smart Web Client')
        # open server socket
        serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # if using http
        if (parsedURL.scheme == 'http' or parsedURL.scheme == False):
            serverSocket.connect((urlunparse(parsedURL)))

if __name__ == "__main__":
    try:
        # TODO: Add proper error handling of bad URIs
        parsedURL = urlparse(sys.argv[1])
        SmartWebClient(parsedURL)
    except ValueError:
        sys.stderr.write('Incorrect URI format. Try again')
    