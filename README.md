# README LiCore-Crypto-IoT
## Condiciones de uso
Al utilizar este código, aceptas cumplir con las siguientes condiciones:

1. No utilizar este código para fines ilegales o no éticos.
3. No utilizar este código para infringir los derechos de autor o propiedad intelectual de terceros.
4. No distribuir ni compartir este código sin mencionar claramente al autor y proporcionar un enlace al repositorio original.

Recuerda que este código es solo una muestra y puede requerir modificaciones para adaptarse a tus necesidades específicas.

Si estás de acuerdo con estas condiciones, siéntete libre de utilizar este código y disfrutar de sus beneficios. 

==============================================================================================================================================================================
## 2. Los requisitos de instalación.
## Dependencias
- Python 3.7
- Librería `socket`
- Librería `ssl`
- Librería `tinyec`
- Librería `pandas`

## Instalación
1. Clona el repositorio.

## Uso
1. Corre el código de `ecdsa_server.py`
2. Corre el código de `ecdsa_client.py` e ingresa la decisión
3. En caso de querer limpiar la base de datos correr el código `ecdsa_client.py`, para su creación nuevamente

    Un ejemplo se puede observar en https://youtu.be/dcRZlVgVFWk
==============================================================================================================================================================================
## 3. Descripción de programa
---. Es decir, cómo construyeron esas funciones y cómo se ocupan. La diferencia con el reporte es que en este último indicarán en dónde usan lo que programaron.
# README del Código del Componente de Cliente

Este repositorio contiene el código del componente de cliente en Python. El código correspondiente se encuentra en el archivo `ecdsa_client.py`.

El componente de cliente implementa el algoritmo EC-DSA (Elliptic Curve Digital Signature Algorithm) para firmar y verificar datos utilizando criptografía de curva elíptica. Además, incluye funcionalidad para intercambiar información con un servidor a través de sockets.


2. El código principal consiste en varias funciones que permiten firmar, verificar y enviar datos al servidor. Estas funciones están definidas en el archivo `ecdsa_client.py`.

3. Modifica el script según sea necesario, proporcionando el conjunto de datos y la información del servidor adecuados:

```python
# Cargar el conjunto de datos
dataset = pd.read_csv(r'Prosumer_ABC.csv', header=0, sep=";")
dataframe = dataset.iloc[0:5]

# Establecer el nombre del servidor y el puerto
hostname = socket.gethostname()
port = 1234

# Llama a la función adecuada para intercambiar mensajes
client_program(dataframe, hostname, port)  # Sin TLS
# client_tls(dataframe, hostname, port)  # Con TLS
```

4. Ejecuta el script:

```shell
python ecdsa_client.py
```

```python
import socket
import ssl
import tinyec
from tinyec import registry
import pickle
import secrets
import hashlib
import pandas as pd
```

5. El script te solicitará acciones: enviar datos (`F`), recibir y verificar datos (`V`), o finalizar el programa. Sigue las indicaciones para interactuar con el servidor.
==============================================================================================================================================================================

## 4. Sus contactos para poder ser consultados por dudas o potenciales ajustes a realizar.
A00831314@tec.mx Paola Sofía Reyes Mancheno; 
A01197399@tec.mx Diana Paola Cadena Nito; 
A01275180@tec.mx Alexis Hernández Spinola; 
A01285041@tec.mx María Fernanda Torres Alcubilla; 
A01705747@tec.mx Enrique García Varela; 
A01730548@tec.mx Javier Hernández Arellano; 

## 5. Licencia
El código en este repositorio está licenciado bajo [Creative Commons Attribution-ShareAlike 4.0 International License (CC BY-SA 4.0)](https://creativecommons.org/licenses/by-sa/4.0/).
