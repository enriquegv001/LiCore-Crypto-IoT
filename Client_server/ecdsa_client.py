import socket
import ssl
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
    
def firmado_dsa(m):
  curve = registry.get_curve('brainpoolP256r1')
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
  return  curve, r, s, Q, m, 
    
#Firmado y lista con la curva, r, s y Q
def firmado_df(df):
  a = []
  for i in df.index: #firmado para cada registro
    curve = registry.get_curve('brainpoolP256r1')
    m = pickle.dumps(df.iloc[i].to_numpy(), protocol=4)
    _,r,s,Q,m = firmado_dsa(m)
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

def info_exchange(client_socket, dataframe):
#-----------------------------Envio de mensajes--------------------
  i = 0
  while i<1:
      decision = input('\nActions:\n-Send (F) \n-Receive (V) \n-End \nSelect your action:\n') #Preguntar
      #message = pickle.dumps(decision, protocol=4) 
      client_socket.send(decision.encode())  # send message 

      if decision == 'F': # cliente como firmado
          """
          mensaje1 = str(firmado_df(dataframe))
          print(len(mensaje1.encode()))
          print(mensaje1)
          client_socket.send(mensaje1.encode())
          """ 
          message = pickle.dumps(firmado_df(dataframe) , protocol=4) 
          #message = firmado_df(m).encode(), 
          #print(len(message))
          client_socket.send(message)  # enviar firmado
          ver = client_socket.recv(65507).decode() # recibir verificacion
          print('Cliente: firmado')
          print('Servidor verificación: ' + str(ver))  # show in terminal
          
      elif decision == 'V': # cliente como verificador
          #envio query
          query = pickle.dumps(input('\nInsert sql query:\n'), protocol=4)
          message = pickle.dumps(firmado_dsa(query), protocol=4)
          client_socket.send(message)


#****************************Experimento buffer bug*********************
          """
          bytes_len = int(client_socket.recv(32).decode()) # cantidad de bytes mensaje a recibir
          # recibir sql por cachos y juntar todo
          message = []
          i = 0
          while i <= bytes_len:  # loop para mostrar bytes por mensaje
            packet = client_socket.recv(65507)
            # if not packet: break
            print(len(packet))
            message.append(packet)
            i += 1
          #message = pickle.loads(b"".join(message))
          message = b"".join(message)
          print(len(message))
          """
#***********************************************************************
          message = client_socket.recv(65507) 
          curve, r, s, Q, m  = pickle.loads(message, encoding='bytes')
          print('message recived...')
          print('\n', verificado_dsa(curve, r, s, Q, m))
          m = pickle.loads(m, encoding='bytes')

          # display the sql
          for row in m:
            for col in row:
                print(col,end=' ')
            print('\n')
            print()



      #elif decision == 'T':
      #   client_socket.send('prueba'.encode())
    

      else: #terminar iteraciones
        i = i + 1

#============================Conexión SSL/TLS=========================
def client_program(m, host, port): #conexión sin TLS
  client_socket = socket.socket()  # instantiate
  print('Socket creado')
  client_socket.connect((host, port))  # connect to the server
  print('Socket conectado')
  info_exchange(client_socket, m)
  client_socket.close()  # close the connection


def client_tls(m, hostname, port):

  context = ssl.create_default_context()
  context.load_verify_locations(r'instance 0\ec-cacert-0.pem')
  sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  print('socket creado')
  ssock = context.wrap_socket(sock, server_hostname=hostname)
  print('socket warpped')
  ssock.connect((hostname, port))
  print('Socket version: ', ssock.version())

  info_exchange(ssock, m)


if __name__ == '__main__':
    #base de datos
    dataset = pd.read_csv(r'Prosumer_ABC.csv', header = 0, sep = ";")
    #curve = registry.get_curve('brainpoolP256r1')
    dataframe = dataset.iloc[0:5]

    #host_public = "ec2-54-164-68-66.compute-1.amazonaws.com" # ec2 mine
    #host_public = "ec-44-204-5-126.compute-1.amazonaws.com"  # teacher
    host_public = socket.gethostname() #aws

    port = 1234

    client_program(dataframe, host_public, port)  #no tls
    #client_tls(dataframe, host_public, port)


