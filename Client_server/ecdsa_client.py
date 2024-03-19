import socket
import ssl
import tinyec
from tinyec import registry
import pickle
import secrets
import hashlib
import pandas as pd

#============================Algoritmos para EC-DSA actual=====================
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

#**************Deterministico de k, modificación del código por:************
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
#*************************************************************************

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

#****************Funciones con comprobación de RFC de curva 256:**********************
#!/usr/bin/python3
# coding: utf-8
#
# Author: Manuel Pégourié-Gonnard.
# SPDX-License-Identifier: Apache-2.0

"""A simple implementation of P-256 (ECDH, ECDSA) for tests."""

import secrets
import hashlib


class ModInt:
    """Modular integer."""

    def __init__(self, x, n):
        """Build x mod n."""
        self.x = x % n
        self.n = n

    def __repr__(self):
        """Represent self."""
        return "ModInt({}, {})".format(self.x, self.n)

    def __int__(self):
        """Return the representant in [0, n)."""
        return self.x

    def __eq__(self, other):
        """Compare to another ModInt."""
        return self.x == other.x and self.n == other.n

    def __add__(self, other):
        """Add to another ModInt."""
        return ModInt(self.x + other.x, self.n)

    def __sub__(self, other):
        """Subtract another ModInt."""
        return ModInt(self.x - other.x, self.n)

    def __neg__(self):
        """Negate self."""
        return ModInt(-self.x, self.n)

    def __mul__(self, other):
        """Multiply by another ModInt."""
        return ModInt(self.x * other.x, self.n)

    def __rmul__(self, other):
        """Multiply self by an integer."""
        return ModInt(self.x * other, self.n)

    def __pow__(self, other):
        """Elevate to an integer power."""
        return ModInt(pow(self.x, other, self.n), self.n)

    def inv(self):
        """Return modular inverse as a ModInt or raise ZeroDivisionError."""
        a, b, u, s = self.x, self.n, 1, 0
        # invariants: a < b and a == u*x mod n and b == s*x mod n
        while a > 1:
            q, r = divmod(b, a)  # r = b - q*a
            a, b, u, s = r, a, s - q*u, u
        if a != 1:
            raise ZeroDivisionError
        return ModInt(u, self.n)

    def __truediv__(self, other):
        """Divide by another ModInt or raise ZeroDivisionError."""
        return self * other.inv()

    def is_zero(self):
        """Tell if we're 0."""
        return self.x == 0


class Curve:
    """Curve parameters - Short Weierstrass curves over GF(p), p > 3."""

    # assuming cofactor of 1 (true for NIST and Brainpool curves),
    # so n is the order of the curve and of the base point G

    def __init__(self, name, *, p, a, b, gx, gy, n):
        """Build a Curve from the given int parameters."""
        self.name = name
        self.p = p
        self.a = ModInt(a, p)
        self.b = ModInt(b, p)
        self.gx = ModInt(gx, p)
        self.gy = ModInt(gy, p)
        self.n = n

        self.p_bits = p.bit_length()
        self.p_bytes = (self.p_bits + 7) // 8

        self.n_bits = n.bit_length()
        self.n_bytes = (self.n_bits + 7) // 8

    def __str__(self):
        """Human-friendly name."""
        return self.name

    def zero(self):
        """Return the origin (point at infinity)."""
        return CurvePoint(None, self)

    def base_point(self):
        """Return this curve's conventional base point."""
        return CurvePoint((self.gx, self.gy), self)


# rfc 6090 app. D, or rfc 5903 3.1, or sec2-v2 2.4.2, or FIPS 186-4 D.1.2.3
p256 = Curve(
    "P-256",
    p=0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF,
    a=-3,
    b=0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B,
    n=0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551,
    gx=0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
    gy=0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
)


class CurvePoint:
    """Point on a Curve."""

    def __init__(self, coordinates, curve):
        """Coordinates is either a pair of ModInt or None for 0."""
        self.coord = coordinates
        self.curve = curve

    def is_zero(self):
        """Tell if this is 0 (aka the origin aka the point at infinity."""
        return self.coord is None

    def x(self):
        """Return the x coordinate as a ModInt."""
        return self.coord[0]

    def y(self):
        """Return the y coordinate as a ModInt."""
        return self.coord[1]

    def __eq__(self, other):
        """Compare to another point on the curve."""
        if self.is_zero() and other.is_zero():
            return True

        if self.is_zero() or other.is_zero():
            return False

        return self.x() == other.x() and self.y() == other.y()

    def __add__(self, other):
        """Add to another point - RFC 6090 Appendix F.1."""
        if self.is_zero():
            return other

        if other.is_zero():
            return self

        x1, y1, x2, y2 = self.x(), self.y(), other.x(), other.y()

        if self != other and x1 == y1:
            return CurvePoint(None, self.curve)

        if self != other:
            x3 = ((y2-y1) / (x2-x1))**2 - x1 - x2
            y3 = (x1-x3) * (y2-y1) / (x2-x1) - y1
            return CurvePoint((x3, y3), self.curve)

        # this can't happen with curves of large prime order,
        # but let's just follow the formulas in the RFC
        if y1.is_zero():
            return CurvePoint(None, self.curve)

        a = self.curve.a
        x3 = ((3*x1**2 + a) / (2*y1))**2 - 2*x1
        y3 = (x1-x3)*(3*x1**2 + a) / (2*y1) - y1
        return CurvePoint((x3, y3), self.curve)

    def __rmul__(self, other):
        """Multiply self by a positive integer (scalar multiplication)."""
        # invariant: result + scale * scalar = self * other
        result = self.curve.zero()
        scale = self
        scalar = other
        while scalar != 0:
            if scalar % 2 != 0:
                result += scale
            scale += scale
            scalar //= 2

        return result


def ecdsa_modint_from_hash(msg_hash, n, nbits):
    """Derive an integer mod n from a message hash for ECDSA."""
    # This is Sec1 4.1.3 step 5 or 4.1.4 step 3
    # Subteps 1-3: simplify when nbits is a multiple of 8
    assert(nbits % 8 == 0)
    use_len = min(32, len(msg_hash))
    msg_hash = msg_hash[:use_len]
    # Substep 4: 2.3.8 says big endian
    e = int.from_bytes(msg_hash, 'big')
    # Extra: mod n
    return ModInt(e, n)


class EcdsaSigner:
    """A private key, able to create ECDSA signatures."""

    def __init__(self, curve, d=None):
        """Create an ECDSA private key for curve or load it from an int."""
        self.curve = curve
        self.d = d if d is not None else self._gen_scalar()
    def show_parm(self):
        print(self.curve, '\n', self.curve.n, '\n', self.curve.n_bits)

    def _gen_scalar(self):
        # sec1 3.2.1: d in [1, n-1] ( = [0, n-1) + 1 )
        return secrets.randbelow(self.curve.n - 1) + 1

    def _gen_public(self, d):
        return d * self.curve.base_point()

    def public_key(self):
        """Return the associated public key as a CurvePoint."""
        return self._gen_public(self.d)

    def sign(self, msg_hash, k=None):
        """Generate a signature (int pair) for that message hash (bytes)."""
        # sec1 4.1.3, but instead of retrying just abort
        n = self.curve.n
        nbits = self.curve.n_bits
        # 1. Set ephemeral keypair
        if k is None:
            k = self._gen_scalar()
        R = self._gen_public(k)
        k = ModInt(k, n)
        # 2, 3. Convert to integer mod n
        r = ModInt(int(R.x()), n)
        assert(not r.is_zero())
        # 4. Skipped - we take the hash as input
        # 5. Derive integer from hash
        e = ecdsa_modint_from_hash(msg_hash, n, nbits)
        # 6. Compute s
        d = ModInt(self.d, n)
        s = (e + r * d) / k
        assert(not s.is_zero())
        # 7. Output two integers
        return (int(r), int(s))


class EcdsaVerifier:
    """An ECDSA public key, able to verify signatures."""

    def __init__(self, curve, public_key):
        """Create an ECDSA verifier from a public key (CurvePoint)."""
        self.curve = curve
        self.Q = public_key

    def is_valid(self, sig, msg_hash):
        """Tell if signature (int pair) is valid for that hash (bytes)."""
        # sec1 4.1.4
        n = self.curve.n
        nbits = self.curve.n_bits
        r, s = sig
        # 1. Verify range
        if not (0 < r < n and 0 < s < n):
            return False
        # 2. Skip hashing - we take the hash as input
        # 3. Derive integer from hash
        e = ecdsa_modint_from_hash(msg_hash, n, nbits)
        # 4. Compute u1, u2
        r = ModInt(r, n)
        s = ModInt(s, n)
        u1 = e / s
        u2 = r / s
        # 5. Compute R
        R = int(u1) * self.curve.base_point() + int(u2) * self.Q
        if R.is_zero():
            return False
        # 6, 7. Convert to v
        v = ModInt(int(R.x()), n)
        # 8. Compare
        return v == r
#*********************************************************************

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
  context.load_verify_locations(r'instance 0\ec-cacert-0.pem') #change to your cert path
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



