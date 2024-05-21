# Sử dụng OpenJDK image để build ứng dụng
FROM maven:3.8.4-openjdk-8 AS build

# Thư mục làm việc mặc định trong container
WORKDIR /app

# Sao chép file pom.xml vào thư mục làm việc
COPY pom.xml .

# Tải các dependencies và cache chúng trong layer riêng
#RUN mvn dependency

# Sao chép mã nguồn vào thư mục làm việc
COPY src ./src
COPY lib ./lib

# Build ứng dụng
RUN mvn package -DskipTests

# Sử dụng một image nhẹ hơn để chạy ứng dụng
FROM openjdk:8-jdk-alpine

# Thư mục làm việc mặc định trong container
WORKDIR /app

# Sao chép file .jar từ image build vào container
COPY --from=build /app/target/sign-1.0.war /app/sign.jar

# Cổng mà ứng dụng Spring Boot lắng nghe
EXPOSE 8080

# Lệnh chạy ứng dụng Spring Boot khi container được khởi động
CMD ["java", "-jar", "sign.jar"]
