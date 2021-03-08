#Se obtiene la imagen desde https://hub.docker.com/
FROM openjdk:14.0
#Se agrega volumen que usa tomcat para guardar log o archivos temporales
VOLUME /tmp
#Se expone el puerto que usará la aplicación
EXPOSE 9100
#Se agrega el archivo jar desde el target hacia una ruta (con nombre) en el docker
ADD ./target/springboot-servicio-oauth-0.0.1-SNAPSHOT.jar oauth-server.jar
#En esta parte le dices el comando que se ejecutará cuando se ejecute el dockerfile (con sintáxis de docker)
ENTRYPOINT ["java","-jar","/oauth-server.jar"]
#Con esto vamos a generar el deploy de la aplicación usando docker
# docker build -t config-server:v1 .
# Se usa el comando de arriba para generar la imagen que desplegara nuestro microservicio, se usa la opción -t para dar un nombre y una versión a la imagen
# docker network create spring-cloud-ms
# Se crea una red de docker para que los microservicios estén comunicados entre sí
# docker run -p 8888:8888 --name config-server --network spring-cloud-ms config-server:v1
#Se ejecuta e contentedor con un puerto, el primero es el puerto externo (maquina local) y el segundo el del propio contenedor
#tabmbién se le asgina un nombre con el cual los demás microservicios se van a counicar con él
#Se le asigna el network al cual estará conectado y se da el nombre de la imagen que se quiere ejecutar con su respectiva verison
# docker container ls | ps -> Para listar las intancias
# docker container stop {id-instancia} para detener la instancia
# docker container rm {id-instancia} para borrar la instancia
#docker container --help -> para ayuda
# docker logs -f {id|nombre-contenedor}
#docker run -p 3306:3306 --name mysql-server8 --network spring-cloud-ms -e MYSQL_ROOT_PASSWORD=password -e MYSQL_DATABASE=db_springboot_cloud -d mysql:8
#con -e se agregan variables de entorno
#