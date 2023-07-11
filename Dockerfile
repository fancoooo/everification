FROM openjdk:8-jdk-alpine
EXPOSE 8080
ADD issuer-config /opt/issuer-config
ARG JAR_FILE=target/sign-1.0.war
ADD ${JAR_FILE} eVerifyService.war
ENTRYPOINT ["java","-jar","/eVerifyService.war"]