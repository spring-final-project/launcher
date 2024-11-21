#!/bin/bash
sudo dnf update -y
echo "export JWT_SECRET=${JWT_SECRET}" | sudo tee -a /etc/environment
echo "export EUREKA_HOST=${EUREKA_HOST}" | sudo tee -a /etc/environment
echo "export EUREKA_PORT=${EUREKA_PORT}" | sudo tee -a /etc/environment
source /etc/environment

# Install AWS X-Ray daemon
sudo dnf update -y && sudo dnf install nmap-ncat -y
wget https://s3.us-east-2.amazonaws.com/aws-xray-assets.us-east-2/xray-daemon/aws-xray-daemon-3.x.rpm && \
    sudo dnf install aws-xray-daemon-3.x.rpm -y && \
    rm aws-xray-daemon-3.x.rpm

# Initialize AWS X-Ray daemon
/usr/bin/xray -o -n sa-east-1

#Install git and java
sudo dnf install git -y
sudo dnf install java-21-amazon-corretto -y

# Clone repo
cd /home/ec2-user
git clone https://github.com/spring-final-project/gateway.git
cd gateway

# Build and run
sudo chmod +x mvnw
sudo ./mvnw clean package -DskipTests
java -jar target/gateway-0.0.1.jar