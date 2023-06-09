import socket
import tinyec
from tinyec import registry
import pickle
import secrets
import hashlib
import pandas as pd

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
  return [curve, r, s, Q, m]


# Firmado y lista con la curva, r, s y Q
def firmado_df(df):
  a = []
  for i in df.index:
    curve = registry.get_curve('brainpoolP256r1')
    m = pickle.dumps(df.iloc[i].to_numpy(), protocol=4)
    r,s,Q,h = firmado_dsa(curve, m)
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
  for i in range(len(a)):
    return verificado_dsa(a[i][0],a[i][1],a[i][2],a[i][3],a[i][4])


#============================Conexión SSL/TLS=========================
def server_program():
  # get the hostname
  host = socket.gethostname()#'172.31.87.162'
  port = 5000  # initiate port no above 1024

  server_socket = socket.socket()  # get instance
  # look closely. The bind() function takes tuple as argument
  server_socket.bind((host, port))  # bind host address and port together
  print('bind socket')
  # configure how many client the server can listen simultaneously
  server_socket.listen(2)
  print('Socket is listening...')
  conn, address = server_socket.accept()  # accept new connection
  print("Connection from: " + str(address))
  #while True:
  # receive data stream. it won't accept data packet greater than 1024 bytes
  decision = pickle.loads(conn.recv(65507), encoding='bytes')
  print("Cliente: " + str(decision))

  #-----------------------------Envio de mensajes--------------------
  i = 0
  while i < 2:
    if decision == 'F':
      par = pickle.loads(conn.recv(65507), encoding='bytes')
      #par = conn.recv(65507).decode()
      #par = conn.recv(65507)
      #print(par)
      print('Recived message')
            #print('Servidor: verificacion')
      print(pickle.loads(par[0][4], encoding = 'bytes')) 
      print(ver_df(par))
      conn.send(ver_df(par).encode())  # enviar verificación al cliente
      print('Sended verification')

    elif decision == 'V': # servidor como firmado, cliente como verificación
      curve = registry.get_curve('brainpoolP256r1')
      m = pickle.dumps('hola', protocol=4)
      r = firmado_dsa(curve, m)
      message = pickle.dumps(r, protocol=4) 
      conn.send(message)  # enviar firmado
      ver = conn.recv(65507).decode() # recibir verificacion
      print('Servidor: firmado')
      print("Cliente verificación: " + str(ver))
    
    
    else: #terminar iteraciones
      i=i +1

  conn.close()  # close the connection
if __name__ == '__main__':
    server_program()
