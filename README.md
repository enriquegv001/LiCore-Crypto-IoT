# README LiCore-Crypto-IoT
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
   
Un ejemplo se puede observar en https://youtu.be/dcRZlVgVFWk

En caso de querer limpiar la base de datos correr el código `Complementary code/ecdsa_client.py`, para su creación nuevamente

## Descripción de programa
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
   - `info_exchange(client_socket, dataframe)`: Función principal que maneja el intercambio de información entre el cliente y el servidor.
   - `server_program(host, port)`: Creación de socket del servidor respecto a una ip privada y un puerto
   - `server_tls(host, port)`: Creación de socket del servidor, a través de certificados CA y la llave públca del protocólo TLS.
   - `client_program(m, host, port)`: Creación de socket del cliente de forma local por medio de por medio de ip pública del servidor, así como su puerto abierto
   - `client_tls(m, hostname, port)`: Creación de socket del cliente aplicando los certificados de la CA del protocólo TLS. Para el cual se requiere tener el archivo .pem generado dentro del servidor. El método seguro para enviar el docuemnto es a través de ssh.


<!---
#### `ecdsa_client.py`

1. Importación de bibliotecas:
   - `socket`: Proporciona funciones para la comunicación de red.
   - `ssl`: Proporciona funciones para el cifrado de comunicaciones utilizando el protocolo SSL/TLS.
   - `tinyec` y `registry`: Bibliotecas para trabajar con criptografía de curva elíptica.
   - `pickle`: Permite la serialización y deserialización de objetos Python.
   - `secrets`: Genera números aleatorios seguros.
   - `hashlib`: Proporciona funciones de hash criptográfico.
   - `pandas`: Biblioteca para la manipulación y análisis de datos.

2. Definición de funciones:
   - `alg_euc_ext(a, b)`: Implementa el algoritmo de Euclides extendido para obtener el inverso de un número en un grupo dado.
   - `firmado_dsa(m)`: Realiza el proceso de firma digital utilizando el algoritmo EC-DSA.
   - `firmado_df(df)`: Aplica el proceso de firma digital a un DataFrame de pandas, generando firmas para cada registro.
   - `verificado_dsa(curve, r, s, Q, m)`: Verifica la firma digital de un mensaje utilizando el algoritmo EC-DSA.
   - `ver_df(a)`: Realiza la verificación de firma para cada registro en una lista de firmas.
   - `info_exchange(client_socket, dataframe)`: Función principal que maneja el intercambio de información entre el cliente y el servidor.

3. Funciones `client_program(m, host, port)` y `client_tls(m, hostname, port)`: Estas funciones establecen la conexión con el servidor y llaman a la función `info_exchange` para iniciar el intercambio de información.

4. Bloque `if __name__ == '__main__':`: Este bloque se ejecuta cuando el script se ejecuta directamente (no cuando se importa como un módulo). En este caso, carga un conjunto de datos de un archivo CSV, establece el host y el puerto, y llama a la función `client_program` para iniciar la conexión sin TLS o a la función `client_tls` para iniciar la conexión con TLS.
-->

## Implementación de fuciones
El programa consiste de dos códigos generales, el primero es el de `ecdsa_server.py` con el que se estan dando los certificados, al estos estar siendo generados en una instancia de ec2 nueva, la ruta de los mismos ya esta automática. Por lo que se etará levantando el servidor después de haber corrido `server_tls(host, port)`, con el que se estará conectando despues de haber corrido `client_tls(m, hostname, port)`. El proceso de enviado de información va a diferenciarse en cada una de las partes, pero ambos utilizan `info_exchange()` con el que se estará ingresando la conexión que será de utilidad para el momento de enviar y recibir los datos.

Con ello se mostrá en pantalla un menú para el cliente sobre la decisión a tomarl. El debe establecer si estará enviando o recibiendo los datos almacenados en la ruta que se establecio de base de datos inical de .csv para el cliente y con la dirección del servidor de SQL para el servidor.

## Contactos
A00831314@tec.mx Paola Sofía Reyes Mancheno; 
A01197399@tec.mx Diana Paola Cadena Nito; 
A01275180@tec.mx Alexis Hernández Spinola; 
A01285041@tec.mx María Fernanda Torres Alcubilla; 
A01705747@tec.mx Enrique García Varela; 
A01730548@tec.mx Javier Hernández Arellano; 

## Licencia
El código en este repositorio está licenciado bajo [Creative Commons Attribution-ShareAlike 4.0 International License (CC BY-SA 4.0)](https://creativecommons.org/licenses/by-sa/4.0/).
