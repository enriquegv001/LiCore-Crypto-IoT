import socket
import tinyec
from tinyec import registry
import pickle
import secrets
import hashlib
import pandas as pd

def alg_euc_ext(a,b):
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

  d = a; x = x2; y = y2
  # y es inverso de a
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
  return  r, s, Q, h
    
#Firmado y lista con la curva, r, s y Q
def firmado_df(df):
  a = []
  for i in df.index:
    curve = registry.get_curve('brainpoolP256r1')
    m = pickle.dumps(df.iloc[i].to_numpy(), protocol=4)
    r,s,Q,h = firmado_dsa(curve, m)
    a.append([curve, r,s,Q,h])
  return a



def verificado_dsa(data):
    curve, r, s, Q, h = data[0], data[1], data[2], data[3], data[4]
    #Generaicón de clave
    q = curve.field.n
    P = curve.g
    
    #Verificación de la firma
    if 1<=r and 1<=s and r<=(q-1) and s<=(q-1):
        w = alg_euc_ext(curve.field.n, s)[2] # invserso s
        u1 = h * w % q
        u2 = r * w % q
        v = (u1*P + u2*Q).x%q
        if v == r:
          return 'Se acepta la firma'
        else:
          return 'Se rechaza la firma'
    else:
        return 'Error: no cumple con 1<=r, s<=q-1'

# Verificación firma
def ver_df(a):
  for i in range(len(a)):
    return verificado_dsa(a[i][0],a[i][1],a[i][2],a[i][3],a[i][4])


def client_program(curve,m):
    host = socket.gethostname()#'131.178.102.128' #'44.203.90.217'  # as both code is running on same pc
    port = 5000  # socket server port number

    client_socket = socket.socket()  # instantiate
    print('Socket creado')
    client_socket.connect((host, port))  # connect to the server
    print('Socket conectado')
    i = 0
    while i<2:
        decision = input('Firmado (f) o verificacion (v): ')
        message = pickle.dumps(decision, protocol=4) # '[100,0]'
        client_socket.send(message)  # send message 

        if decision == 'f': # cliente como firmado
            r = firmado_df(m)
            #message = firmado_df(m).encode()
            message = pickle.dumps(r, protocol=4) 
            client_socket.send(message)  # enviar firmado
            ver = client_socket.recv(65507).decode() # recibir verificacion
            print('Cliente: firmado')
            print('Servidor verificación: ' + str(ver))  # show in terminal
            
        else: # cliente como verificador
            data = pickle.loads(client_socket.recv(65507), encoding='bytes') # recibir parámetros firmado
            client_socket.send(verificado_dsa(data).encode())  # enviar verificación
            print('Cliente: verificador')
        
        i = i + 1

    client_socket.close()  # close the connection


if __name__ == '__main__':
    dataset = pd.read_csv(r'C:\Users\Enrique\Downloads\Cripto Reto\Client\Prosumer_ABC.csv', header = 0, sep = ";")
    curve = registry.get_curve('brainpoolP256r1')
    #m = pickle.dumps(dataset.iloc[0:5], protocol=4)
    m = dataset.iloc[0:5]
    client_program(curve, m)