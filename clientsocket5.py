import socket
import ssl

#hostname = "ec2-44-204-5-126.compute-1.amazonaws.com"
hostname = "ec2-35-175-217-227.compute-1.amazonaws.com"


print('p1')
context = ssl.create_default_context()
print('p2')
#context.load_verify_locations('C:\\Users\\Enrique\\Downloads\\ec-cacert.pem')
context.load_verify_locations('C:\\Users\\Enrique\\Downloads\\Cripto Reto\\Client\\new\\ec-cacert-inst4.pem')
print('context done')
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
print('socket creado')
ssock = context.wrap_socket(sock, server_hostname=hostname)
#ssock = ssl.wrap_socket(sock, certfile = 'ec-cacert.pem')
print('socket warpped')
ssock.connect((hostname, 1234))
print('Socket version: ', ssock.version())
#ssock.send("test".encode())
#print(ssock.recv(1000).decode())
#ssock.send()