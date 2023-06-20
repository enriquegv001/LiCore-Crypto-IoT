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
    

#Deterministico de k, modificación del código por:
#https://pycoin.readthedocs.io/en/latest/_modules/pycoin/ecdsa/rfc6979.html#:~:text=%5Bdocs%5D%20def%20deterministic_generate_k%28generator_order%2C%20secret_exponent%2C%20val%2C%20hash_f%3Dhashlib.sha256%29%3A%20%22%22%22%20%3Aparam,%2B%20b%27x00%27%2C%20hash_f%29.digest%28%29%20v%20%3D%20hmac.new%28k%2C%20v%2C%20hash_f%29.digest%28%29
import hashlib
import hmac

if hasattr(1, "bit_length"):
    def bit_length(v):
        return v.bit_length()
else:
    def bit_length(self):
        s = bin(self)  # binary representation:  bin(-37) --> '-0b100101'
        s = s.lstrip('-0b')  # remove leading zeros and minus sign
        return len(s)  # len('100101') --> 6

def deterministic_k(generator_order, secret_exponent, val , hash_f):
    n = generator_order
    bln = bit_length(n)
    order_size = (bln + 7) // 8
    hash_size = hash_f().digest_size
    v = b'\x01' * hash_size
    k = b'\x00' * hash_size
    priv_key = int.to_bytes(secret_exponent, byteorder = 'big', length=order_size)
    h1 = int(hashlib.sha256(val).hexdigest(), 16)
    h1 = h1.to_bytes(32, 'big')
    k = hmac.new(k, v + b'\x00' + priv_key + h1, hash_f).digest()
    v = hmac.new(k, v, hash_f).digest()
    k = hmac.new(k, v + b'\x01' + priv_key + h1, hash_f).digest()
    v = hmac.new(k, v, hash_f).digest()

    while 1:
        t = bytearray()
        while len(t) < order_size:
            v = hmac.new(k, v, hash_f).digest()
            t.extend(v)
        k1 = int.from_bytes(bytes(t), 'big')
        if k1 >= 1 and k1 < n:
            return k1


# firmado ecdsa para mensajes encodeados
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
    #k = secrets.randbelow(q)
    k = deterministic_k(q, x, m , hashlib.sha256)
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



