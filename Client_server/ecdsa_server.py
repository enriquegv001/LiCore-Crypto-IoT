import socket
import ssl
import tinyec
from tinyec import registry
import pickle
import secrets
import hashlib
import pandas as pd
import mysql.connector as SQLC
import time

#============================Algoritmos para EC-DSA=====================
def alg_euc_ext(a,b): # obtener inverso de a, del grupo b 
    if b == 0:
        d = a; x = 1; y =0
        return d,x, y
    
    x1 = 0; x2 = 1; y1 = 1; y2 = 0
    
    while b != 0:
        q = int(a/b)
        r = a - q*b
        x = x2 - q*x1
        y = y2 - q*y1
        a = b
        b = r
        x2 =x1
        x1 = x
        y2 = y1
        y1 = y
        
    d = a; x = x2; y = y2 # y es el inverso 
    return d,x,y

def firmado_dsa(curve, m):
  # Generación de clave
  q = curve.field.n
  P = curve.g # element G of prime order q is chosen in E(GF(p))
  x = secrets.randbelow(q) #privkey
  Q = x * P # pubkey
  #h = hashlib.sha1(m)
  h = int(hashlib.sha512(m).hexdigest(),16)
  #Firma digital
  r = 0
  s = 0

  while r == 0 or s == 0:
    k = secrets.randbelow(q)
    kP = k * P
    r = kP.x % q 
    l = alg_euc_ext(q, k)[2] # inverso de k
    s = (l*(h + x*r))%q 
  return  curve, r, s, Q, m
    
#Firmado y lista con la curva, r, s y Q
def firmado_df(df):
  a = []
  for i in df.index: #firmado para cada registro
    curve = registry.get_curve('brainpoolP256r1')
    m = pickle.dumps(df.iloc[i].to_numpy(), protocol=4)
    _,r,s,Q,m = firmado_dsa(curve, m)
    a.append([curve, r,s,Q,m])
  return a

def verificado_dsa(curve, r, s, Q, m):
    #curve, r, s, Q, h = data[0], data[1], data[2], data[3], data[4]
    #Generaicón de clave
    q = curve.field.n
    P = curve.g
    
    #Verificación de la firma
    if 1<=r and 1<=s and r<=(q-1) and s<=(q-1):
        w = alg_euc_ext(curve.field.n, s)[2] # invserso s
        h = int(hashlib.sha512(m).hexdigest(),16)
        u1 = h * w % q
        u2 = r * w % q
        v = (u1*P + u2*Q).x%q
        if v == r:
          return 'Se acepta la firma'
        else:
          return 'Se rechaza la firma'
    else:
    	return 'Error: no cumple con 1<=r, s<=q-1'

# Verificación firma para cada registro
def ver_df(a):  
  updated_row = 0 # contador de lineas correctas
  for i in range(len(a)):
    curve, r, s, Q, m = a[i]
    ver = verificado_dsa(curve, r, s, Q, m) #formado para cada linea, ingresando llaves y menaje
    if ver == 'Se acepta la firma':
      row = pd.Series(pickle.loads(m, encoding='bytes')).astype(str) #mensaje desencriptado
      print(row)

      #subir datos a mysql, a db = TEST1, table = db1
      sql = "INSERT INTO TEST1.db1 VALUES ({}%s)".format("%s," * 100)
      Cursor.execute(sql, tuple(row))
      print('\n\n\n\n', ver, '\n', type(row), 'upladed')
      updated_row += 1
    
    else:
       print('Registro ', i,':', ver)
    
    time.sleep(1)
  
  DataBase.commit()
  return 'termino de cargar y se subieron {} registros'.format(updated_row)


def info_exchange(conn):
     #-----------------------------Envio de mensajes--------------------
  i = 0
  while i < 1:
    # receive data stream. it won't accept data packet greater than 1024 bytes
    #decision = pickle.loads(conn.recv(65507), encoding='bytes')
    decision = conn.recv(65507).decode()
    print("\n Cliente: " + str(decision))

    if decision == 'F':  
      mess1 = conn.recv(65507)
      par = pickle.loads(mess1, encoding='bytes')
      conn.send(ver_df(par).encode())  # enviar verificación al cliente
      

    elif decision == 'V': # servidor como firmado, cliente como verificación
      query = pickle.loads(conn.recv(65507), encoding='bytes')
      curve, r, s, Q, m = query
      print('query: ',pickle.loads(m, encoding='bytes'), '\n')
      print(verificado_dsa(curve, r, s, Q, m))
      try:
        Cursor.execute(pickle.loads(m, encoding='bytes'))
        res = Cursor.fetchall()
        
      except:
         res = 'Query se ingreso mal'
         print('Query se ingreso mal')
         
      #dataset = pd.read_csv(r'Prosumer_ABC.csv', header = 0, sep = ";") #Change to get the data from database
      #m = dataset.iloc[0:2]
      curve = registry.get_curve('brainpoolP256r1')
      res = pickle.dumps(res, protocol=4)
  
      message = pickle.dumps(firmado_dsa(curve, res), protocol=4)

      #Si es mensaje mayor el que el buffer size entonces dividir en n cantidades
      bytes_len = len(message)
      if bytes_len <= 65507:
        n = 1
      else:
        n = int(bytes_len / 65507) 
      conn.send(str(n).encode())

      #se envía por partes de tamaño igual
      conn.send(message[:65507])
      for i in range(1, n+1):
         m_inter = message[65507*i:65507*(i+1)] #selecciona intermedios
         conn.send(m_inter)
      conn.send(message[65507*n:])
      print('message sended')


     # conn.send(message)  # enviar firmado

    else: #terminar iteraciones
      i=i +1


#============================Conexión SSL/TLS=========================
def server_program(host, port):
  server_socket = socket.socket()  # get instance
  # look closely. The bind() function takes tuple as argument
  server_socket.bind((host, port))  # bind host address and port together
  print('bind socket')
  # configure how many client the server can listen simultaneously
  server_socket.listen(2)
  print('Socket is listening...')
  conn, address = server_socket.accept()  # accept new connection
  print("Connection from: " + str(address))

  info_exchange(conn)
    
  server_socket.close()
    

def server_tls(host, port):
  context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
  #context.load_verify_locations('/home/ec2-user/root/tls/certs/ec-cacert.pem', '/home/ec2-user/root/tls/private/ec-cakey.pem')
  context.load_cert_chain('/home/ec2-user/root/tls/certs/ec-cacert.pem', '/home/ec2-user/root/tls/private/ec-cakey.pem')
  with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
          sock.bind((host, port))
          sock.listen(5)
          print('Server listening...')
          with context.wrap_socket(sock, server_side=True) as ssock:
                  print('Socket warpped')
                  conn, addr = ssock.accept()

                  print('Client with: ', addr)
                  info_exchange(conn)

                  ssock.close()
          sock.close()


if __name__ == '__main__':
    host_private = socket.gethostname() #local
    #host_private = '172.31.91.109' # ec2
    
    port = 1234

    DataBase = SQLC.connect(
    host ="databaseiot.cbzpcvsds3vs.us-east-1.rds.amazonaws.com",
    user ="admin",
    password ="Topos2023",
    database ="TEST1"
    )

    # Cursor a la database
    Cursor = DataBase.cursor()

    server_program(host_private, port) #no tls
    #server_tls(host_private, port)
