
import socket
import ssl

#HOST =  '107.20.0.228'
HOST = 'ec2-107-20-0-228.compute-1.amazonaws.com'
PORT = 8443
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
ssl_socket = ssl.wrap_socket(client_socket, cert_reqs=ssl.CERT_REQUIRED, ca_certs = 'server.crt')

try:
 ssl_socket.connect((HOST, PORT))
 message = 'Hello, server!'
 ssl_socket.send(message.encode())
 
 response = ssl_socket.recv(1024)
 print('Recived:', response.decode())
 ssl_socket.close()

except ssl.SSLError as e:
 print('SSL error: ', e)

except socket.error as e:
 print('Socket error: ', e)



"""
#context = ssl.create_default_context()

#with socket.create_connection((HOST, PORT)) as sock:
# with context.wrap_socket(sock, server_hostname = HOST) as ssock:
#        print(ssock.version())

#context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
#context.load_verify_locations('Desktop/client.pem')
#client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#cleint_socket.connect((HOST, PORT))


# PROTOCOL_TLS_CLIENT requires valid cert chain and hostname
context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
context.load_verify_locations('client.crt')

with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
    with context.wrap_socket(sock, server_hostname=HOST) as ssock:
        print(ssock.version())

#data = sock.recv(80)
#print('Received', data.decode())



sock.close()

"""
