#!/bin/bash

# Install git and java
sudo dnf update -y
sudo dnf install git -y
sudo dnf install java-21-amazon-corretto -y

# Clone repo
cd /home/ec2-user
git clone https://github.com/spring-final-project/eureka-ms.git
cd eureka-ms

# Build and run
sudo chmod +x mvnw
sudo ./mvnw clean package -DskipTests
java -jar target/eureka-ms-0.0.1.jar