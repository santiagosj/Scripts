#!/usr/bin/env python3
from http.server import HTTPServer, BaseHTTPRequestHandler
import os

class SimpleUploadHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        filename = self.headers.get('X-Filename', 'loot.zip')

        with open(filename, 'wb') as f:
            f.write(post_data)

        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"File received.")

if __name__ == '__main__':
    os.chdir('/tmp')  # o cualquier otro directorio donde quieras guardar
    server = HTTPServer(('0.0.0.0', 8000), SimpleUploadHandler)
    print("Listening on port 8000 for uploads...")
    server.serve_forever()
