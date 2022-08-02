FROM openjdk:8-jdk-alpine
VOLUME /tmp
RUN apk --no-cache add curl
ADD ./target/spring-boot-demo.jar app.jar
ENTRYPOINT ["java","-Djava.security.egd=file:/dev/./urandom","-jar","/app.jar"]