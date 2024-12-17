import http.server
import socketserver
import urllib.parse as urlparse
import json
from hashlib import sha256

# Store users in memory (can be replaced with a database)
users = {
    "farmer1": {"password": sha256("password123".encode()).hexdigest(), "type": "farmer"},
    "retailer1": {"password": sha256("password123".encode()).hexdigest(), "type": "retailer"},
}

# Define a handler for processing HTTP requests
class LoginHandler(http.server.SimpleHTTPRequestHandler):
    def do_POST(self):
        # Parse the request path
        parsed_path = urlparse.urlparse(self.path)
        user_type = parsed_path.path.strip("/").split("_")[0]  # Extract "farmer" or "retailer"

        # Read and decode the POST data
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        form_data = urlparse.parse_qs(post_data.decode('utf-8'))

        username = form_data.get("username", [None])[0]
        password = form_data.get("password", [None])[0]

        # Check if the user exists and the password matches
        if username and password:
            user = users.get(username)
            if user and user["type"] == user_type and user["password"] == sha256(password.encode()).hexdigest():
                # Successful login
                self.send_response(200)
                self.send_header("Content-type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"status": "success", "message": f"Welcome, {user_type} {username}!"}).encode())
            else:
                # Invalid login
                self.send_response(401)
                self.send_header("Content-type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"status": "error", "message": "Invalid credentials or user type"}).encode())
        else:
            # Missing credentials
            self.send_response(400)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"status": "error", "message": "Missing username or password"}).encode())

    def do_GET(self):
        # Serve static files (like your HTML login page)
        super().do_GET()

# Start the server
PORT = 8080
with socketserver.TCPServer(("", PORT), LoginHandler) as httpd:
    print(f"Server started at http://127.0.0.1:{PORT}")
    httpd.serve_forever()
