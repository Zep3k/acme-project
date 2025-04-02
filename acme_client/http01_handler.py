from http.server import BaseHTTPRequestHandler

class HTTP01Handler(BaseHTTPRequestHandler):
    token = ""
    key_auth = ""
    def do_GET(self):
        if self.path == f"/.well-known/acme-challenge/{self.token}":
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.end_headers()
            self.wfile.write(self.key_auth.encode("ascii"))
        else:
            self.send_response(200)
            self.end_headers()
            with open("acme_client/cert.pem", "r") as cert_file:
                self.wfile.write(cert_file.read())
    def do_HEAD(self):
        self.send_response(200)
        self.end_headers()