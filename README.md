# Documentación LiCore-Crypto-IoT
## Condiciones de uso
Al utilizar este código, aceptas cumplir con las siguientes condiciones:

1. No utilizar este código para fines ilegales o no éticos.
3. No utilizar este código para infringir los derechos de autor o propiedad intelectual de terceros.
4. No distribuir ni compartir este código sin mencionar claramente al autor y proporcionar un enlace al repositorio original.

Recuerda que este código es solo una muestra y puede requerir modificaciones para adaptarse a tus necesidades específicas.

Si estás de acuerdo con estas condiciones, siéntete libre de utilizar este código y disfrutar de sus beneficios. 


## Requeriminetos de uso

### Los requisitos de instalación.
#### Dependencias
- Python 3.7
- Librería `socket`
- Librería `ssl`
- Librería `tinyec`
- Librería `pandas`
- Librería `pickle`
- Librería `secrets`
- Librería `hashlib`
- Librería `mysql.connector`
- Librería `time`


### Instalación
1. Clona del repositorio.
2. Abre la carpeta de `Client-Server` 
3. Crea una instancia AWS EC2 siguiendo tutorial https://docs.aws.amazon.com/es_es/AWSEC2/latest/UserGuide/EC2_GetStarted.html
4. Crea los certificados CA (solo el 5to paso del tutorial): https://www.golinuxcloud.com/openssl-generate-ecc-certificate/#5_Create_CA_certificate_with_ECC_Key
5. Configura el el código de `ecdsa_server.py` para ingresar los certificados de CA y su llave privada. Después corre código en la instancia EC2
6. Crea un auditor Rasbperry en una Máquina Virtual https://roboticsbackend.com/install-raspbian-desktop-on-a-virtual-machine-virtualbox/#Install_VirtualBox
7. Compartir a través de ssh certificado a máquina virual del auditor
8. Abrir algun puerto TCP el cual será el que se indique dentro del código para realizar la conexión actualmente esta el 1234
9. Cambia en código de `ecdsa_client.py` la variable `host_public` a la ip correspondiente a la de la instancia EC2 y correlo en la VM
10. ingresa la decisión de `Enviar(F)` o `Recibir(V)`
   
Un ejemplo se puede observar en el [Video](https://youtu.be/h-keUv-cJzo)

En caso de querer limpiar la base de datos correr el código `Complementary code/ecdsa_client.py`, para su creación nuevamente

## Descripción de programa
Este repositorio cuenta con las carpetas de `Artículo y presentación` dónde se puede observar el trabajo realizado para la matería, así como `Client_server` la cual será la carpeta a descargar, ya que en ella vienen los códigos que incluyen todo el funcionamiento de los componentes correspodinetes al auditor `ecdsa_client.py`, el código del servidor `ecdsa_server.py`, así como la base de datos `Prosumer_ABC.csv` y la carpeta de `instance 0` que incluye a las llaves para poder realizar la conexión entre las máquinas virtuales del protoyipo, sin embargo, será necesario generar unos nuevos, los pasos a seguir en instalación.

También, esta la carpeta de `Complementary code` en la que se puede obtener los códigos de prueba que se utilizaron para resolver las distintas funciones del programa por separado. En dicha carpeta se encuentra  `ECDSA_RFC_vectores_prueba.ipynb` el cual contiene dos métodos de firmado y verificación, uno el cual esta comprobado que se adapta a los requisitos del informe https://www.rfc-editor.org/rfc/rfc6979#appendix-A.2.5 y otro que es el acutual y que hasta el momento solo se tiene el determinístico para obtener k. Así mismo, estan los docuemntos de `clientsocket5.py` y `socketserver.py` en los que se establece las primeras conexiones por medio de certificados TLS. 


Este repositorio en Python proporcionado es un programa Cliente Servidor que establece una conexión utilizando sockets y protocolo TLS. El programa permite enviar y recibir mensajes a través  la firma y verificación de datos utilizando el algoritmo EC-DSA (Elliptic Curve Digital Signature Algorithm).

A continuación se explica cada una de las funciones y secciones del código:

[comment]: <> (#### `ecdsa_server.py`)

 1. Bibliotecas utilizadas
    El código utiliza las siguientes bibliotecas:
    
    - `socket`: Proporciona una interfaz de red de bajo nivel para la programación de sockets.
    - `ssl`: Permite la encriptación SSL/TLS para una comunicación segura.
    - `tinyec`: Una biblioteca para operaciones de criptografía de curva elíptica.
    - `pickle`: Biblioteca de serialización utilizada para la serialización de objetos.
    - `secrets`: Genera números aleatorios seguros.
    - `hashlib`: Proporciona varios algoritmos de hash.
    - `pandas`: Biblioteca para la manipulación y análisis de datos.
    - `mysql.connector`: Biblioteca de conexión para bases de datos MySQL.
    - `time`: Proporciona funciones para operaciones relacionadas con el tiempo.
   
2. Definición de funciones:
   - `alg_euc_ext(a, b)`: Implementa el algoritmo de Euclides extendido para obtener el inverso de un número en un grupo dado.
   - `deterministic_k(generator_order, secret_exponent, val , hash_f)`: La cual generará al valor de k, correspondiente a las longitudes de los mensajes dadas la funciones de  `bit_length(v)`, así como su proceso definido por el informe RFC6979
   - `firmado_dsa(m)`: Realiza el proceso de firma digital utilizando el algoritmo EC-DSA.
   - `firmado_df(df)`: Aplica el proceso de firma digital a un DataFrame de pandas, generando firmas para cada registro.
   - `verificado_dsa(curve, r, s, Q, m)`: Verifica la firma digital de un mensaje utilizando el algoritmo EC-DSA.
   - `ver_df(a)`: Realiza la verificación de firma para cada registro en una lista de firmas.
   - `bit_length()`: para objetos enteros. Si es así, define una función bit_length(v) que simplemente devuelve v.bit_length(). Si no existe bit_length() en el objeto int, se define una función bit_length(self) que calcula la longitud en bits del número entero mediante la conversión a una representación binaria y contando los dígitos binarios.
   - `deterministic_k(a)`: utiliza el orden del generador para determinar el tamaño necesario en bytes para representar el orden. Luego, se inicializan variables y se realizan operaciones de hash y autenticación de mensajes basadas en HMAC para generar el valor determinístico k dentro del rango [1, n), donde n es el orden del generador.
   - `info_exchange(client_socket, dataframe)`: Función principal que maneja el intercambio de información entre el cliente y el servidor.
   - `server_program(host, port)`: Creación de socket del servidor respecto a una ip privada y un puerto
   - `server_tls(host, port)`: Creación de socket del servidor, a través de certificados CA y la llave públca del protocólo TLS.
   - `client_program(m, host, port)`: Creación de socket del cliente de forma local por medio de por medio de ip pública del servidor, así como su puerto abierto
   - `client_tls(m, hostname, port)`: Creación de socket del cliente aplicando los certificados de la CA del protocólo TLS. Para el cual se requiere tener el archivo .pem generado dentro del servidor. El método seguro para enviar el docuemnto es a través de ssh.

#### clases dentro de vectores de prueba:
  - `MonInt`:proporciona una implementación para realizar operaciones aritméticas modulares, incluyendo suma, resta, multiplicación, potenciación y división, así como métodos para obtener el inverso modular y verificar si el objeto ModInt es igual a cero.
  - `Curve`: proporciona una forma de representar los parámetros de una curva elíptica de Weierstrass corta sobre un campo finito. También incluye métodos para obtener el punto en el infinito y el punto base de la curva.
  - `CurvePoint`: proporciona métodos para trabajar con puntos en una curva elíptica. Incluye funcionalidades como verificación de igualdad de puntos, suma de puntos y multiplicación por escalar.
  - `EcdsaSigner` representa una clave privada capaz de crear firmas ECDSA, mientras que la clase EcdsaVerifier representa una clave pública capaz de verificar firmas ECDSA. Ambas clases utilizan objetos de clase Curve y CurvePoint para realizar los cálculos y verificaciones necesarios en el esquema de firma ECDSA.
  - Funciones:
           - ecdsa_modint_from_hash toma un valor hash de un mensaje y lo deriva en un entero módulo n para su uso en el esquema de firma ECDSA (Elliptic Curve Digital Signature Algorithm).
           - 

## Implementación de fuciones
El programa consiste de dos códigos generales, el primero es el de `ecdsa_server.py` con el que se estan dando los certificados, al estos estar siendo generados en una instancia de ec2 nueva, la ruta de los mismos ya esta automática. Por lo que se etará levantando el servidor después de haber corrido `server_tls(host, port)`, con el que se estará conectando despues de haber corrido `client_tls(m, hostname, port)`. El proceso de enviado de información va a diferenciarse en cada una de las partes, pero ambos utilizan `info_exchange()` con el que se estará ingresando la conexión que será de utilidad para el momento de enviar y recibir los datos.

Con ello se mostrá en pantalla un menú para el cliente sobre la decisión a tomarl. El debe establecer si estará enviando o recibiendo los datos almacenados en la ruta que se establecio de base de datos inical de .csv para el cliente y con la dirección del servidor de SQL para el servidor. 

Dependiendo de la decisión, al compoentne que le corresponda enviar la información aplciará la función de `firmado_df(df)`, la cual a su vez estará utilizando `alg_euc_ext(a, b)`, `firmado_dsa(m)` y `deterministic_k(generator_order, secret_exponent, val , hash_f)`. Desepués se enviará los datos y al momento de recibirlos, los cual se realiza por medio de la misma función de `info_exchange()`, estos estarán siendo verificados con la función de `ver_df(a)` y se desplegarán en la pantalla.

## Contactos
A01705747@tec.mx Enrique García Varela

A00831314@tec.mx Paola Sofía Reyes Mancheno

A01197399@tec.mx Diana Paola Cadena Nito

A01275180@tec.mx Alexis Hernández Spinola

A01285041@tec.mx María Fernanda Torres Alcubilla
 
A01730548@tec.mx Javier Hernández Arellano

## Licencia
El código en este repositorio está licenciado bajo [Creative Commons Attribution-ShareAlike 4.0 International License (CC BY-SA 4.0)](https://creativecommons.org/licenses/by-sa/4.0/).
