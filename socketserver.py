import socket
import ssl 

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain('/etc/pki/tls/certs/server.crt', '/etc/pki/tls/private/server.key')

with socket.socket(socket.AF_INET, socket.SOCK_STREAM)as s:
 s.bind(('0.0.0.0', 49152))
 s.listen(5)
 with context.wrap_socket(s, server_side = True) as ssock:
  conn, addr = ssock.accept()

while True:
    clientsocket, adress = s.accept()
    print("Connection  has been established!")