terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region      = var.region
  access_key  = var.access_key
  secret_key  = var.secret_key
}

########################################################################################

# VPC AND SUBNETS

########################################################################################

# Create a VPC
resource "aws_vpc" "main_vpc" {
  cidr_block = "10.0.0.0/16"
}

# Create Internet Gateway
resource "aws_internet_gateway" "gw" {
  vpc_id = aws_vpc.main_vpc.id
}

# Create a public subnets in the VPC
resource "aws_subnet" "public_subnet" {
  vpc_id            = aws_vpc.main_vpc.id
  cidr_block        = "10.0.1.0/24"
  availability_zone = var.availability_zones[0]
}

resource "aws_subnet" "public_subnet_2" {
  vpc_id            = aws_vpc.main_vpc.id
  cidr_block        = "10.0.2.0/24"
  availability_zone = var.availability_zones[1]
}

# Create a private subnets in the VPC
resource "aws_subnet" "private_subnet" {
  vpc_id            = aws_vpc.main_vpc.id
  cidr_block        = "10.0.3.0/24"
  availability_zone = var.availability_zones[0]
}

resource "aws_subnet" "private_subnet_2" {
  vpc_id            = aws_vpc.main_vpc.id
  cidr_block        = "10.0.4.0/24"
  availability_zone = var.availability_zones[1]
}

# Create Route Tables for public subnets
resource "aws_route_table" "ig_rt" {
  vpc_id = aws_vpc.main_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.gw.id
  }
}

# Associate public subnets to Route Tables
resource "aws_route_table_association" "public_subnet_rt_association" {
  subnet_id      = aws_subnet.public_subnet.id
  route_table_id = aws_route_table.ig_rt.id
}

resource "aws_route_table_association" "public_subnet_rt_association_2" {
  subnet_id      = aws_subnet.public_subnet_2.id
  route_table_id = aws_route_table.ig_rt.id
}

# Access to internet from private subnets
resource "aws_eip" "nat_eip" {
  domain = "vpc"
  depends_on = [aws_internet_gateway.gw]
}

resource "aws_nat_gateway" "nat_gw" {
  allocation_id = aws_eip.nat_eip.id
  subnet_id     = aws_subnet.public_subnet.id
}

resource "aws_route_table" "private_route_table" {
  vpc_id = aws_vpc.main_vpc.id
}

resource "aws_route_table_association" "private_route_assoc" {
  subnet_id      = aws_subnet.private_subnet.id
  route_table_id = aws_route_table.private_route_table.id
}

resource "aws_route" "private_route_to_nat" {
  route_table_id         = aws_route_table.private_route_table.id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.nat_gw.id
}

########################################################################################

# LOAD BALANCER

########################################################################################

# Create security group for ALB
resource "aws_security_group" "alb_sg" {
  name    = "alb sg"
  vpc_id   = aws_vpc.main_vpc.id

  ingress {
    from_port       = 80
    to_port         = 80
    protocol        = "tcp"
    cidr_blocks     = ["0.0.0.0/0"]
  }

  ingress {
    from_port       = 8761
    to_port         = 8761
    protocol        = "tcp"
    cidr_blocks     = ["0.0.0.0/0"]
  }

  egress {
    from_port       = 0
    to_port         = 0
    protocol        = "-1"
    cidr_blocks     = ["0.0.0.0/0"]
  }
}

# Create a load balancer in front system
resource "aws_lb" "app_alb" {
  name               = "app-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb_sg.id]
  subnets            = [aws_subnet.public_subnet.id, aws_subnet.public_subnet_2.id]
}

# Create Load Balancer Listener for HTTP
resource "aws_lb_listener" "http_listener" {
  load_balancer_arn = aws_lb.app_alb.arn
  port              = 80
  protocol          = "HTTP"
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.gateway_tg.arn
  }
}

# Create Load Balancer Listener for Eureka
resource "aws_lb_listener" "eureka_listener" {
  load_balancer_arn = aws_lb.app_alb.arn
  port              = 8761
  protocol          = "HTTP"
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.eureka_tg.arn
  }
}

########################################################################################

# POLICIES

########################################################################################

# XRay policy
resource "aws_iam_policy" "xray_policy" {
  name = "XRayPolicy"
  description = "IAM policy for X-Ray daemon"
  policy = jsonencode({
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Action": [
          "xray:PutTraceSegments",
          "xray:PutTelemetryRecords",
        ],
        "Resource": "*"
      }
    ]
  })
}

########################################################################################

# KAFKA

########################################################################################

resource "aws_security_group" "kafka_sg" {
  name        = "kafka_sg"
  description = "Allow access to Kafka"
  vpc_id      = aws_vpc.main_vpc.id

  ingress {
    from_port       = 9092
    to_port         = 9092
    protocol        = "tcp"
    cidr_blocks     = ["10.0.3.0/24"]
  }

  egress {
    from_port       = 0
    to_port         = 0
    protocol        = "-1"
    cidr_blocks     = ["0.0.0.0/0"]
  }
}

resource "aws_msk_configuration" "kafka_configuration" {
  name           = "kafka-config"

  server_properties = <<PROPERTIES
  auto.create.topics.enable=true
  PROPERTIES
}

resource "aws_msk_cluster" "kafka_cluster" {
  cluster_name           = "kafka-cluster"
  kafka_version          = "3.7.x"
  number_of_broker_nodes = 2
  depends_on = [aws_msk_configuration.kafka_configuration]

  broker_node_group_info {
    instance_type        = "kafka.m5.large"
    client_subnets       = [aws_subnet.private_subnet.id, aws_subnet.private_subnet_2.id]
    security_groups      = [aws_security_group.kafka_sg.id]
  }

  configuration_info {
    arn = aws_msk_configuration.kafka_configuration.arn
    revision = aws_msk_configuration.kafka_configuration.latest_revision
  }

  tags = {
    Name = "kafka-cluster"
  }
}

########################################################################################

# GATEWAY

########################################################################################

# Create target group for gateway instances
resource "aws_lb_target_group" "gateway_tg" {
  name     = "gateway-tg"
  port     = 8080
  protocol = "HTTP"
  vpc_id   = aws_vpc.main_vpc.id
}

# Create security group for Gateway service
resource "aws_security_group" "gateway_sg" {
  name    = "gateway asg sg"
  vpc_id   = aws_vpc.main_vpc.id

  ingress {
    from_port       = 8080
    to_port         = 8080
    protocol        = "tcp"
    security_groups = [aws_security_group.alb_sg.id]
  }

  ingress {
    from_port       = 22
    to_port         = 22
    protocol        = "tcp"
    cidr_blocks     = var.allowed_ssh_ips
  }

  egress {
    from_port       = 0
    to_port         = 0
    protocol        = "-1"
    cidr_blocks     = ["0.0.0.0/0"]
  }
}

# EC2 gateway role
resource "aws_iam_role" "ec2_gateway_role" {
  name = "EC2GatewayRole"

  assume_role_policy = jsonencode({
    "Version": "2012-10-17",
    "Statement": [
      {
        "Action": "sts:AssumeRole",
        "Principal": {
          "Service": "ec2.amazonaws.com"
        },
        "Effect": "Allow",
        "Sid": ""
      }
    ]
  })
}

# Attach policy to EC2 role
resource "aws_iam_role_policy_attachment" "ec2_gateway_role_policy_attachment" {
  role       = aws_iam_role.ec2_gateway_role.name
  policy_arn = aws_iam_policy.xray_policy.arn
}

# IAM instance profile
resource "aws_iam_instance_profile" "ec2_gateway_profile" {
  name = "EC2GatewayProfile"
  role = aws_iam_role.ec2_gateway_role.name
}

# Create Auto Scaling Group for gateway service
resource "aws_autoscaling_group" "gateway_asg" {
  availability_zones   = [var.availability_zones[0]]
  min_size             = 1
  max_size             = 3
  desired_capacity     = 1
  target_group_arns    = [aws_lb_target_group.gateway_tg.arn]
  launch_template {
    id = aws_launch_template.gateway_template.id
    version = "$Latest"
  }
}

# Create launch template for gateway service
resource "aws_launch_template" "gateway_template" {
  name_prefix                           = "gateway-lt-"
  image_id                              = var.ami
  instance_type                         = var.instance_type
  instance_initiated_shutdown_behavior  = "terminate"
  depends_on                            = [aws_instance.eureka]

  iam_instance_profile {
    name = aws_iam_instance_profile.ec2_gateway_profile.name
  }

  network_interfaces {
    associate_public_ip_address = true
    security_groups             = [aws_security_group.gateway_sg.id]
    subnet_id                   = aws_subnet.public_subnet.id
  }

  block_device_mappings {
    device_name = "/dev/sdf"

    ebs {
      volume_size           = 8
      delete_on_termination = true
    }
  }

  monitoring {
    enabled = true
  }

  tag_specifications {
    resource_type = "instance"

    tags = {
      "Name" = "gateway"
    }
  }

  user_data = base64encode(templatefile("scripts/gateway.sh", {
    JWT_SECRET  = var.jwt_secret
    EUREKA_HOST = aws_instance.eureka.private_ip
    EUREKA_PORT = 8761
  }))
}

########################################################################################

# EUREKA

########################################################################################

# Create target group for gateway instances
resource "aws_lb_target_group" "eureka_tg" {
  name     = "eureka-tg"
  port     = 8761
  protocol = "HTTP"
  vpc_id   = aws_vpc.main_vpc.id
}

# Attach gateway instances to target group
resource "aws_lb_target_group_attachment" "eureka_attachment" {
  target_group_arn = aws_lb_target_group.eureka_tg.arn
  target_id        = aws_instance.eureka.id
  port             = 8761
}

# Create security group for Eureka service
resource "aws_security_group" "eureka_sg" {
  name    = "eureka asg sg"
  vpc_id  = aws_vpc.main_vpc.id

  ingress {
    from_port       = 8761
    to_port         = 8761
    protocol        = "tcp"
    security_groups = [aws_security_group.alb_sg.id, aws_security_group.gateway_sg.id, aws_security_group.users_sg.id, aws_security_group.auth_sg.id, aws_security_group.rooms_sg.id, aws_security_group.asks_sg.id, aws_security_group.bookings_sg.id]
  }

  ingress {
    from_port       = 22
    to_port         = 22
    protocol        = "tcp"
    cidr_blocks     = var.allowed_ssh_ips
  }

  egress {
    from_port       = 0
    to_port         = 0
    protocol        = "-1"
    cidr_blocks     = ["0.0.0.0/0"]
  }
}

# Create EC2 instance for Eureka service
resource "aws_instance" "eureka" {
  ami             = var.ami
  instance_type   = var.instance_type
  subnet_id       = aws_subnet.public_subnet.id
  security_groups = [aws_security_group.eureka_sg.id]
  associate_public_ip_address = true

  tags = {
    Name = "eureka-instance"
  }

  user_data = templatefile("scripts/eureka.sh",{})
}

########################################################################################

# USERS

########################################################################################

resource "aws_security_group" "users_sg" {
  name    = "users_sg"
  vpc_id   = aws_vpc.main_vpc.id

  ingress {
    from_port       = 8080
    to_port         = 8080
    protocol        = "tcp"
    security_groups = [aws_security_group.gateway_sg.id, aws_security_group.auth_sg.id]
  }

  egress {
    from_port       = 0
    to_port         = 0
    protocol        = "-1"
    cidr_blocks     = ["0.0.0.0/0"]
  }
}

# EC2 user role
resource "aws_iam_role" "ec2_user_role" {
  name = "EC2UserRole"

  assume_role_policy = jsonencode({
    "Version": "2012-10-17",
    "Statement": [
      {
        "Action": "sts:AssumeRole",
        "Principal": {
          "Service": "ec2.amazonaws.com"
        },
        "Effect": "Allow",
        "Sid": ""
      }
    ]
  })
}

# Attach policy to EC2 role
resource "aws_iam_role_policy_attachment" "users_xray_attach" {
  role       = aws_iam_role.ec2_user_role.name
  policy_arn = aws_iam_policy.xray_policy.arn
}

resource "aws_iam_role_policy_attachment" "users_ssm_attach" {
  role       = aws_iam_role.ec2_user_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

# IAM instance profile
resource "aws_iam_instance_profile" "ec2_user_profile" {
  name = "EC2UserProfile"
  role = aws_iam_role.ec2_user_role.name
}

# Create a Auto Scaling Group for Users service
resource "aws_autoscaling_group" "users_asg" {
  availability_zones = [var.availability_zones[0]]
  min_size             = 1
  max_size             = 3
  desired_capacity     = 1
  name = "users-asg"

  launch_template {
    id      = aws_launch_template.users_template.id
    version = "$Latest"
  }
}

# Create launch template for Users service
resource "aws_launch_template" "users_template" {
  name_prefix                           = "users-lt-"
  image_id                              = var.ami
  instance_type                         = var.instance_type
  instance_initiated_shutdown_behavior  = "terminate"

  depends_on = [aws_db_instance.users_db, aws_instance.eureka]

  iam_instance_profile {
    name = aws_iam_instance_profile.ec2_user_profile.name
  }

  network_interfaces {
    security_groups = [aws_security_group.users_sg.id]
    subnet_id = aws_subnet.private_subnet.id
  }

  block_device_mappings {
    device_name = "/dev/sdf"

    ebs {
      volume_size = 8
      delete_on_termination = true
    }
  }

  monitoring {
    enabled = true
  }

  tag_specifications {
    resource_type = "instance"
    tags = {
      Name = "users-ms"
    }
  }

  user_data = base64encode(templatefile("scripts/users.sh", {
    USERS_DB_NAME     = aws_db_instance.users_db.db_name
    USERS_DB_HOST     = aws_db_instance.users_db.address
    USERS_DB_PORT     = aws_db_instance.users_db.port
    USERS_DB_USERNAME = aws_db_instance.users_db.username
    USERS_DB_PASSWORD = aws_db_instance.users_db.password
    EUREKA_HOST       = aws_instance.eureka.private_ip
    EUREKA_PORT       = 8761
  }))
}

resource "aws_security_group" "users_db_sg" {
  name        = "users_db_sg"
  vpc_id      = aws_vpc.main_vpc.id
  description = "Allow access to Users DB"

  ingress {
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    security_groups = [aws_security_group.users_sg.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_db_subnet_group" "users_db_subnet_group" {
  name       = "users_rds_subnet_group"
  subnet_ids = [aws_subnet.private_subnet.id, aws_subnet.private_subnet_2.id]
}

# Create RDS postgres for Users service
resource "aws_db_instance" "users_db" {
  identifier           = "users-db"
  allocated_storage    = 10
  engine               = "postgres"
  engine_version       = "16.3"
  instance_class       = "db.t3.micro"
  vpc_security_group_ids = [aws_security_group.users_db_sg.id]
  db_subnet_group_name = aws_db_subnet_group.users_db_subnet_group.name
  db_name              = var.users_db_name
  username             = var.users_db_username
  password             = var.users_db_password
  skip_final_snapshot  = true
  backup_retention_period = 0
  storage_type = "gp2"
  multi_az = false
}

# Get first instance info of users service
data "aws_autoscaling_group" "users_asg_info" {
  name = aws_autoscaling_group.users_asg.name
}

data "aws_instances" "user_instances_info" {
  filter {
    name = "tag:aws:autoscaling:users-asg"
    values = [data.aws_autoscaling_group.users_asg_info.name]
  }
}

########################################################################################

# AUTH

########################################################################################

# Auth Security Group
resource "aws_security_group" "auth_sg" {
  name    = "auth_sg"
  vpc_id   = aws_vpc.main_vpc.id

  ingress {
    from_port       = 8080
    to_port         = 8080
    protocol        = "tcp"
    security_groups = [aws_security_group.gateway_sg.id]
  }

  egress {
    from_port       = 0
    to_port         = 0
    protocol        = "-1"
    cidr_blocks     = ["0.0.0.0/0"]
  }
}

# EC2 auth role
resource "aws_iam_role" "ec2_auth_role" {
  name = "EC2UAuthRole"

  assume_role_policy = jsonencode({
    "Version": "2012-10-17",
    "Statement": [
      {
        "Action": "sts:AssumeRole",
        "Principal": {
          "Service": "ec2.amazonaws.com"
        },
        "Effect": "Allow",
        "Sid": ""
      }
    ]
  })
}

# Attach policy to EC2 role
resource "aws_iam_role_policy_attachment" "auth_xray_attach" {
  role       = aws_iam_role.ec2_auth_role.name
  policy_arn = aws_iam_policy.xray_policy.arn
}

resource "aws_iam_role_policy_attachment" "auth_ssm_attach" {
  role       = aws_iam_role.ec2_auth_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

# IAM instance profile
resource "aws_iam_instance_profile" "ec2_auth_profile" {
  name = "EC2AuthProfile"
  role = aws_iam_role.ec2_auth_role.name
}

# Create a Auto Scaling Group for Auth service
resource "aws_autoscaling_group" "auth_asg" {
  availability_zones = [var.availability_zones[0]]
  min_size             = 1
  max_size             = 3
  desired_capacity     = 1

  launch_template {
    id      = aws_launch_template.auth_template.id
    version = "$Latest"
  }
}

# Create launch template for Auth service
resource "aws_launch_template" "auth_template" {
  name_prefix                           = "auth-lt-"
  image_id                              = var.ami
  instance_type                         = var.instance_type
  instance_initiated_shutdown_behavior  = "terminate"

  depends_on = [aws_instance.eureka]

  iam_instance_profile {
    name = aws_iam_instance_profile.ec2_auth_profile.name
  }

  network_interfaces {
    security_groups = [aws_security_group.auth_sg.id]
    subnet_id = aws_subnet.private_subnet.id
  }

  block_device_mappings {
    device_name = "/dev/sdf"

    ebs {
      volume_size = 8
      delete_on_termination = true
    }
  }

  monitoring {
    enabled = true
  }

  tag_specifications {
    resource_type = "instance"
    tags = {
      Name = "auth-ms"
    }
  }

  user_data = base64encode(templatefile("scripts/auth.sh", {
    EUREKA_HOST       = aws_instance.eureka.private_ip
    EUREKA_PORT       = 8761
  }))
}

########################################################################################

# ROOMS

########################################################################################

resource "aws_security_group" "rooms_sg" {
  name    = "rooms_sg"
  vpc_id   = aws_vpc.main_vpc.id

  ingress {
    from_port       = 8080
    to_port         = 8080
    protocol        = "tcp"
    security_groups = [aws_security_group.gateway_sg.id, aws_security_group.asks_sg.id, aws_security_group.bookings_sg.id] # aws_security_group.kafka_sg.id
  }

  egress {
    from_port       = 0
    to_port         = 0
    protocol        = "-1"
    cidr_blocks     = ["0.0.0.0/0"]
  }
}

# EC2 rooms role
resource "aws_iam_role" "ec2_rooms_role" {
  name = "EC2RoomsRole"

  assume_role_policy = jsonencode({
    "Version": "2012-10-17",
    "Statement": [
      {
        "Action": "sts:AssumeRole",
        "Principal": {
          "Service": "ec2.amazonaws.com"
        },
        "Effect": "Allow",
        "Sid": ""
      }
    ]
  })
}

# Attach policy to EC2 role
resource "aws_iam_role_policy_attachment" "rooms_xray_attach" {
  role       = aws_iam_role.ec2_rooms_role.name
  policy_arn = aws_iam_policy.xray_policy.arn
}

resource "aws_iam_role_policy_attachment" "rooms_ssm_attach" {
  role       = aws_iam_role.ec2_rooms_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

# Policy for S3 bucket
resource "aws_iam_policy" "rooms_s3_bucket_policy" {
  name = "RoomsS3BucketPolicy"
  description = "IAM policy for S3 bucket"
  depends_on = [aws_s3_bucket.rooms_bucket]

  policy = jsonencode({
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Action": [
          "s3:PutObject",
          "s3:GetObject",
          "s3:DeleteObject"
        ],
        "Resource": "arn:aws:s3:::spring-final-project-rooms/*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "rooms_s3_bucket_policy_attach" {
  role       = aws_iam_role.ec2_rooms_role.name
  policy_arn = aws_iam_policy.rooms_s3_bucket_policy.arn
}

# IAM instance profile
resource "aws_iam_instance_profile" "ec2_rooms_profile" {
  name = "EC2RoomsProfile"
  role = aws_iam_role.ec2_rooms_role.name
}

# Create a Auto Scaling Group for Rooms service
resource "aws_autoscaling_group" "rooms_asg" {
  availability_zones = [var.availability_zones[0]]
  min_size             = 1
  max_size             = 3
  desired_capacity     = 1
  name = "rooms-asg"

  launch_template {
    id      = aws_launch_template.rooms_template.id
    version = "$Latest"
  }
}

# Create launch template for Rooms service
resource "aws_launch_template" "rooms_template" {
  name_prefix                           = "rooms-lt-"
  image_id                              = var.ami
  instance_type                         = var.instance_type
  instance_initiated_shutdown_behavior  = "terminate"

  depends_on = [aws_db_instance.rooms_db, aws_instance.eureka] # aws_msk_cluster.kafka_cluster

  iam_instance_profile {
    name = aws_iam_instance_profile.ec2_rooms_profile.name
  }

  network_interfaces {
    security_groups = [aws_security_group.rooms_sg.id]
    subnet_id = aws_subnet.private_subnet.id
  }

  block_device_mappings {
    device_name = "/dev/sdf"

    ebs {
      volume_size = 8
      delete_on_termination = true
    }
  }

  monitoring {
    enabled = true
  }

  tag_specifications {
    resource_type = "instance"
    tags = {
      Name = "rooms-ms"
    }
  }

  user_data = base64encode(templatefile("scripts/rooms.sh", {
    USERS_DB_NAME     = aws_db_instance.rooms_db.db_name
    USERS_DB_HOST     = aws_db_instance.rooms_db.address
    USERS_DB_PORT     = aws_db_instance.rooms_db.port
    USERS_DB_USERNAME = aws_db_instance.rooms_db.username
    USERS_DB_PASSWORD = aws_db_instance.rooms_db.password
    EUREKA_HOST       = aws_instance.eureka.private_ip
    EUREKA_PORT       = 8761
    KAFKA_URL         = "localhost:9092" # aws_msk_cluster.kafka_cluster.bootstrap_brokers_tls
    S3_BUCKET_NAME    = aws_s3_bucket.rooms_bucket.bucket
  }))
}

resource "aws_security_group" "rooms_db_sg" {
  name        = "rooms_db_sg"
  vpc_id      = aws_vpc.main_vpc.id
  description = "Allow access to Users DB"

  ingress {
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    security_groups = [aws_security_group.rooms_sg.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_db_subnet_group" "rooms_db_subnet_group" {
  name       = "rooms_rds_subnet_group"
  subnet_ids = [aws_subnet.private_subnet.id, aws_subnet.private_subnet_2.id]
}

# Create RDS postgres for Rooms service
resource "aws_db_instance" "rooms_db" {
  identifier           = "rooms-db"
  allocated_storage    = 10
  engine               = "postgres"
  engine_version       = "16.3"
  instance_class       = "db.t3.micro"
  vpc_security_group_ids = [aws_security_group.rooms_db_sg.id]
  db_subnet_group_name = aws_db_subnet_group.rooms_db_subnet_group.name
  db_name              = var.rooms_db_name
  username             = var.rooms_db_username
  password             = var.rooms_db_password
  skip_final_snapshot  = true
  backup_retention_period = 0
  storage_type = "gp2"
  multi_az = false
}

# Create S3 bucket for Rooms service
resource "aws_s3_bucket" "rooms_bucket" {
  bucket = "spring-final-project-rooms"
  force_destroy = true

  tags = {
    Name        = "spring-final-project-rooms"
    Environment = "Prod"
  }
}

resource "aws_s3_bucket_public_access_block" "rooms_bucket_public_access" {
  bucket = aws_s3_bucket.rooms_bucket.id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_s3_bucket_policy" "rooms_bucket_policy" {
  bucket = aws_s3_bucket.rooms_bucket.id
  depends_on = [aws_s3_bucket_public_access_block.rooms_bucket_public_access]
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowPublicRead"
        Effect    = "Allow"
        Principal = "*"
        Action    = "s3:GetObject"
        Resource  = "arn:aws:s3:::spring-final-project-rooms/*"
      },
    ]
  })
}

# Get first instance info of rooms service
data "aws_autoscaling_group" "rooms_asg_info" {
  name = aws_autoscaling_group.rooms_asg.name
}

data "aws_instances" "rooms_instances_info" {
  filter {
    name = "tag:aws:autoscaling:rooms-asg"
    values = [data.aws_autoscaling_group.rooms_asg_info.name]
  }
}

########################################################################################

# ASKS

########################################################################################

resource "aws_security_group" "asks_sg" {
  name    = "asks_sg"
  vpc_id   = aws_vpc.main_vpc.id

  ingress {
    from_port       = 8080
    to_port         = 8080
    protocol        = "tcp"
    security_groups = [aws_security_group.gateway_sg.id] # aws_security_group.kafka_sg.id
  }

  egress {
    from_port       = 0
    to_port         = 0
    protocol        = "-1"
    cidr_blocks     = ["0.0.0.0/0"]
  }
}

# EC2 asks role
resource "aws_iam_role" "ec2_asks_role" {
  name = "EC2AsksRole"

  assume_role_policy = jsonencode({
    "Version": "2012-10-17",
    "Statement": [
      {
        "Action": "sts:AssumeRole",
        "Principal": {
          "Service": "ec2.amazonaws.com"
        },
        "Effect": "Allow",
        "Sid": ""
      }
    ]
  })
}

# Attach policy to EC2 role
resource "aws_iam_role_policy_attachment" "asks_xray_attach" {
  role       = aws_iam_role.ec2_asks_role.name
  policy_arn = aws_iam_policy.xray_policy.arn
}

resource "aws_iam_role_policy_attachment" "asks_ssm_attach" {
  role       = aws_iam_role.ec2_asks_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

# IAM instance profile
resource "aws_iam_instance_profile" "ec2_asks_profile" {
  name = "EC2AsksProfile"
  role = aws_iam_role.ec2_asks_role.name
}

# Create a Auto Scaling Group for Asks service
resource "aws_autoscaling_group" "asks_asg" {
  availability_zones = [var.availability_zones[0]]
  min_size             = 1
  max_size             = 3
  desired_capacity     = 1

  launch_template {
    id      = aws_launch_template.asks_template.id
    version = "$Latest"
  }
}

# Create launch template for Asks service
resource "aws_launch_template" "asks_template" {
  name_prefix                           = "asks-lt-"
  image_id                              = var.ami
  instance_type                         = var.instance_type
  instance_initiated_shutdown_behavior  = "terminate"

  depends_on = [aws_db_instance.asks_db, aws_instance.eureka] # aws_msk_cluster.kafka_cluster

  iam_instance_profile {
    name = aws_iam_instance_profile.ec2_asks_profile.name
  }

  network_interfaces {
    security_groups = [aws_security_group.asks_sg.id]
    subnet_id = aws_subnet.private_subnet.id
  }

  block_device_mappings {
    device_name = "/dev/sdf"

    ebs {
      volume_size = 8
      delete_on_termination = true
    }
  }

  monitoring {
    enabled = true
  }

  tag_specifications {
    resource_type = "instance"
    tags = {
      Name = "asks-ms"
    }
  }

  user_data = base64encode(templatefile("scripts/asks.sh", {
    USERS_DB_NAME     = aws_db_instance.asks_db.db_name
    USERS_DB_HOST     = aws_db_instance.asks_db.address
    USERS_DB_PORT     = aws_db_instance.asks_db.port
    USERS_DB_USERNAME = aws_db_instance.asks_db.username
    USERS_DB_PASSWORD = aws_db_instance.asks_db.password
    EUREKA_HOST       = aws_instance.eureka.private_ip
    EUREKA_PORT       = 8761
    KAFKA_URL         = "localhost:9092" # aws_msk_cluster.kafka_cluster.bootstrap_brokers_tls
  }))
}

resource "aws_security_group" "asks_db_sg" {
  name        = "asks_db_sg"
  vpc_id      = aws_vpc.main_vpc.id
  description = "Allow access to Asks DB"

  ingress {
    from_port   = 3306
    to_port     = 3306
    protocol    = "tcp"
    security_groups = [aws_security_group.asks_sg.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_db_subnet_group" "asks_db_subnet_group" {
  name       = "asks_rds_subnet_group"
  subnet_ids = [aws_subnet.private_subnet.id, aws_subnet.private_subnet_2.id]
}

# Create RDS postgres for Asks service
resource "aws_db_instance" "asks_db" {
  identifier           = "asks-db"
  allocated_storage    = 10
  engine               = "mysql"
  engine_version       = "8.0.39"
  instance_class       = "db.t3.micro"
  vpc_security_group_ids = [aws_security_group.asks_db_sg.id]
  db_subnet_group_name = aws_db_subnet_group.asks_db_subnet_group.name
  db_name              = var.asks_db_name
  username             = var.asks_db_username
  password             = var.asks_db_password
  skip_final_snapshot  = true
  backup_retention_period = 0
  storage_type = "gp2"
  multi_az = false
}

########################################################################################

# BOOKINGS

########################################################################################

resource "aws_security_group" "bookings_sg" {
  name    = "bookings_sg"
  vpc_id   = aws_vpc.main_vpc.id

  ingress {
    from_port       = 8080
    to_port         = 8080
    protocol        = "tcp"
    security_groups = [aws_security_group.gateway_sg.id] # aws_security_group.kafka_sg.id
  }

  egress {
    from_port       = 0
    to_port         = 0
    protocol        = "-1"
    cidr_blocks     = ["0.0.0.0/0"]
  }
}

# EC2 bookings role
resource "aws_iam_role" "ec2_bookings_role" {
  name = "EC2BookingsRole"

  assume_role_policy = jsonencode({
    "Version": "2012-10-17",
    "Statement": [
      {
        "Action": "sts:AssumeRole",
        "Principal": {
          "Service": "ec2.amazonaws.com"
        },
        "Effect": "Allow",
        "Sid": ""
      }
    ]
  })
}

# Attach policy to EC2 role
resource "aws_iam_role_policy_attachment" "bookings_xray_attach" {
  role       = aws_iam_role.ec2_bookings_role.name
  policy_arn = aws_iam_policy.xray_policy.arn
}

resource "aws_iam_role_policy_attachment" "bookings_ssm_attach" {
  role       = aws_iam_role.ec2_bookings_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

# IAM instance profile
resource "aws_iam_instance_profile" "ec2_bookings_profile" {
  name = "EC2BookingsProfile"
  role = aws_iam_role.ec2_bookings_role.name
}

# Create a Auto Scaling Group for Bookings service
resource "aws_autoscaling_group" "bookings_asg" {
  availability_zones = [var.availability_zones[0]]
  min_size             = 1
  max_size             = 3
  desired_capacity     = 1

  launch_template {
    id      = aws_launch_template.bookings_template.id
    version = "$Latest"
  }
}

# Create launch template for Bookings service
resource "aws_launch_template" "bookings_template" {
  name_prefix                           = "bookings-lt-"
  image_id                              = var.ami
  instance_type                         = var.instance_type
  instance_initiated_shutdown_behavior  = "terminate"

  depends_on = [aws_db_instance.bookings_db, aws_instance.eureka] # aws_msk_cluster.kafka_cluster

  iam_instance_profile {
    name = aws_iam_instance_profile.ec2_bookings_profile.name
  }

  network_interfaces {
    security_groups = [aws_security_group.bookings_sg.id]
    subnet_id = aws_subnet.private_subnet.id
  }

  block_device_mappings {
    device_name = "/dev/sdf"

    ebs {
      volume_size = 8
      delete_on_termination = true
    }
  }

  monitoring {
    enabled = true
  }

  tag_specifications {
    resource_type = "instance"
    tags = {
      Name = "bookings-ms"
    }
  }

  user_data = base64encode(templatefile("scripts/bookings.sh", {
    USERS_DB_NAME     = aws_db_instance.bookings_db.db_name
    USERS_DB_HOST     = aws_db_instance.bookings_db.address
    USERS_DB_PORT     = aws_db_instance.bookings_db.port
    USERS_DB_USERNAME = aws_db_instance.bookings_db.username
    USERS_DB_PASSWORD = aws_db_instance.bookings_db.password
    EUREKA_HOST       = aws_instance.eureka.private_ip
    EUREKA_PORT       = 8761
    KAFKA_URL         = "localhost:9092" # aws_msk_cluster.kafka_cluster.bootstrap_brokers_tls
  }))
}

resource "aws_security_group" "bookings_db_sg" {
  name        = "bookings_db_sg"
  vpc_id      = aws_vpc.main_vpc.id
  description = "Allow access to Bookings DB"

  ingress {
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    security_groups = [aws_security_group.bookings_sg.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_db_subnet_group" "bookings_db_subnet_group" {
  name       = "bookings_rds_subnet_group"
  subnet_ids = [aws_subnet.private_subnet.id, aws_subnet.private_subnet_2.id]
}

# Create RDS postgres for Bookings service
resource "aws_db_instance" "bookings_db" {
  identifier           = "bookings-db"
  allocated_storage    = 10
  engine               = "postgres"
  engine_version       = "16.3"
  instance_class       = "db.t3.micro"
  vpc_security_group_ids = [aws_security_group.bookings_db_sg.id]
  db_subnet_group_name = aws_db_subnet_group.bookings_db_subnet_group.name
  db_name              = var.bookings_db_name
  username             = var.bookings_db_username
  password             = var.bookings_db_password
  skip_final_snapshot  = true
  backup_retention_period = 0
  storage_type = "gp2"
  multi_az = false
}

########################################################################################

# Receipts

########################################################################################

# Security Group
resource "aws_security_group" "receipts_sg" {
  name        = "receipts-sg"
  vpc_id      = aws_vpc.main_vpc.id

  # Necesario para invocar MSK
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# Rol de ejecución de Lambda
resource "aws_iam_role" "receipts_lambda_role" {
  name = "receipts-lambda-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })
}

# Necessary for to be inside VPC
resource "aws_iam_role_policy_attachment" "receipts_vpc_attach" {
  role       = aws_iam_role.receipts_lambda_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"
}

# Necessary for MSK
resource "aws_iam_role_policy_attachment" "receipts_kafka_attach" {
  role       = aws_iam_role.receipts_lambda_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonMSKReadOnlyAccess"
}

# Policy for S3 bucket
resource "aws_iam_policy" "receipts_s3_bucket_policy" {
  name = "RecetipsS3BucketPolicy"
  description = "IAM policy for S3 bucket"
  depends_on = [aws_s3_bucket.receipts_bucket]

  policy = jsonencode({
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Action": [
          "s3:PutObject",
          "s3:GetObject",
          "s3:DeleteObject"
        ],
        "Resource": "arn:aws:s3:::spring-final-project-receipts/*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "receipts_s3_bucket_policy_attach" {
  role       = aws_iam_role.receipts_lambda_role.name
  policy_arn = aws_iam_policy.receipts_s3_bucket_policy.arn
}

# Compile receipts-ms
resource "null_resource" "receipts_build_application" {
  provisioner "local-exec" {
    command = "./mvnw clean package -DskipTests || mvnw clean package -DskipTests"
  }
}

# Create S3 bucket for code deploy
resource "aws_s3_bucket" "receipts_deploy_bucket" {
  bucket = "spring-final-project-receipts-deploy"
  force_destroy = true
}

resource "aws_s3_object" "receipts_code" {
  bucket = aws_s3_bucket.receipts_deploy_bucket.id
  key    = "receipts-ms-0.0.1-aws.jar"
  source = "${path.module}/target/receipts-ms-0.0.1-aws.jar"
  depends_on = [null_resource.receipts_build_application]
}

# Allow MSK to invoke Lambda
resource "aws_lambda_permission" "allow_msk_receipts" {
  statement_id  = "AllowMSKInvokeReceipts"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.receipts_lambda.function_name
  principal     = "kafka.amazonaws.com"
  source_arn    = aws_msk_cluster.kafka_cluster.arn
}

# Create trigger MSK-Lambda
resource "aws_lambda_event_source_mapping" "receipts_msk_trigger" {
  event_source_arn  = aws_msk_cluster.kafka_cluster.arn
  function_name     = aws_lambda_function.receipts_lambda.function_name
  starting_position = "TRIM_HORIZON"
  topics            = ["BOOKING_CREATED_TOPIC"]
}

resource "aws_lambda_function" "receipts_lambda" {
  function_name = "receipts-lambda"
  role          = aws_iam_role.receipts_lambda_role.arn
  handler       = "org.springframework.cloud.function.adapter.aws.FunctionInvoker::handleRequest"
  runtime       = "java21"
  s3_bucket     = aws_s3_bucket.receipts_deploy_bucket.id
  s3_key        = aws_s3_object.receipts_code.key
  memory_size   = 512
  timeout       = 30
  depends_on    = [aws_s3_object.receipts_code]

  vpc_config {
    subnet_ids         = [aws_subnet.private_subnet.id]
    security_group_ids = [aws_security_group.receipts_sg.id]
  }
  environment {
    variables = {
      MAIN_CLASS      = "com.springcloud.demo.bookingreceipt.BookingReceiptApplication"
      USERS_MS_URL    = data.aws_instances.user_instances_info[0].private_ips[0]
      ROOMS_MS_URL    = data.aws_instances.rooms_instances_info[0].private_ips[0]
      KAFKA_URL       = "localhost:9092" # aws_msk_cluster.kafka_cluster.bootstrap_brokers_tls
      S3_BUCKET_NAME  = "spring-final-project-receipts"
    }
  }
}

# Create S3 bucket for Receipts service
resource "aws_s3_bucket" "receipts_bucket" {
  bucket = "spring-final-project-receipts"
  force_destroy = true

  tags = {
    Name        = "spring-final-project-receipts"
    Environment = "Prod"
  }
}

resource "aws_s3_bucket_public_access_block" "receipts_bucket_public_access" {
  bucket = aws_s3_bucket.receipts_bucket.id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_s3_bucket_policy" "receipts_bucket_policy" {
  bucket = aws_s3_bucket.receipts_bucket.id
  depends_on = [aws_s3_bucket_public_access_block.receipts_bucket_public_access]
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowPublicRead"
        Effect    = "Allow"
        Principal = "*"
        Action    = "s3:GetObject"
        Resource  = "arn:aws:s3:::spring-final-project-receipts/*"
      },
    ]
  })
}

########################################################################################

# Emails

########################################################################################

# Security Group
resource "aws_security_group" "emails_sg" {
  name        = "emails-sg"
  vpc_id      = aws_vpc.main_vpc.id
}

# Rol de ejecución de Lambda
resource "aws_iam_role" "emails_lambda_role" {
  name = "emails-lambda-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })
}

# Necessary for to be inside VPC
resource "aws_iam_role_policy_attachment" "emails_vpc_attach" {
  role       = aws_iam_role.emails_lambda_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"
}

# Necessary for MSK
resource "aws_iam_role_policy_attachment" "emails_kafka_attach" {
  role       = aws_iam_role.emails_lambda_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonMSKReadOnlyAccess"
}

# Compile emails-ms
resource "null_resource" "build_application" {
  provisioner "local-exec" {
    command = "./mvnw clean package -DskipTests || mvnw clean package -DskipTests"
  }
}

# Create S3 bucket for code deploy
resource "aws_s3_bucket" "emails_deploy_bucket" {
  bucket = "spring-final-project-emails-deploy"
  force_destroy = true
}

resource "aws_s3_object" "emails_code" {
  bucket = aws_s3_bucket.emails_deploy_bucket.id
  key    = "emails-ms-0.0.1-aws.jar"
  source = "${path.module}/target/emails-ms-0.0.1-aws.jar"
  depends_on = [null_resource.build_application]
}

# Allow MSK to invoke Lambda
resource "aws_lambda_permission" "allow_msk_emails" {
  statement_id  = "AllowMSKInvokeEmails"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.emails_lambda.function_name
  principal     = "kafka.amazonaws.com"
  source_arn    = aws_msk_cluster.kafka_cluster.arn
}

# Create trigger MSK-Lambda
resource "aws_lambda_event_source_mapping" "msk_trigger" {
  event_source_arn  = aws_msk_cluster.kafka_cluster.arn
  function_name     = aws_lambda_function.emails_lambda.function_name
  starting_position = "TRIM_HORIZON"
  topics            = ["ASK_CREATED_TOPIC","BOOKING_CREATED_TOPIC","BOOKING_RECEIPT_GENERATED_TOPIC"]
}

resource "aws_lambda_function" "emails_lambda" {
  function_name = "emails-lambda"
  role          = aws_iam_role.emails_lambda_role.arn
  handler       = "org.springframework.cloud.function.adapter.aws.FunctionInvoker::handleRequest"
  runtime       = "java21"
  s3_bucket     = aws_s3_bucket.emails_deploy_bucket.id
  s3_key        = aws_s3_object.emails_code.key
  memory_size   = 512
  timeout       = 30
  depends_on    = [aws_s3_object.emails_code]

  vpc_config {
    subnet_ids         = [aws_subnet.private_subnet.id]
    security_group_ids = [aws_security_group.emails_sg.id]
  }

  environment {
    variables = {
      MAIN_CLASS      = "com.springcloud.demo.emailsmicroservice.EmailMicroserviceApplication"
      USERS_MS_URL    = data.aws_instances.user_instances_info[0].private_ips[0]
      ROOMS_MS_URL    = data.aws_instances.rooms_instances_info[0].private_ips[0]
      KAFKA_URL       = "localhost:9092" # aws_msk_cluster.kafka_cluster.bootstrap_brokers_tls
      EMAIL_ACCOUNT   = var.email_account
      EMAIL_PASSWORD  = var.email_password
    }
  }
}