import socket
import ssl 


context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain('/home/ec2-user/root/tls/certs/ec-cacert.pem', '/home/ec2-user/root/tls/private/ec-cakey.pem')
with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
        sock.bind(('172.31.93.163', 1234))
        sock.listen(5)
        print('Server listening...')
        with context.wrap_socket(sock, server_side=True) as ssock:
                print('Socket warpped')
                conn, addr = ssock.accept()
                print('Client with: ', addr)
                print('Data received')
                data = conn.recv(1024)
                print('Client says: ', data.decode())
                conn.send('thanks!'.encode())
                ssock.close()
        sock.close()