
variable "vpc_id_1" {
  description = "vpc-0941974af902677af"
  type        = string
}

variable "vpc_id_2" {
  description = "vpc-08c48a150e68216da"
  type        = string
}

variable "subnet_id_1" {
  description = "subnet-0b7a8a48f865e42c7"
  type        = string
}

variable "subnet_id_2" {
  description = "subnet-01b73b85331985e9d"
  type        = string
}

module "vpc-1" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "5.16.0"
  name    = "group1-vpc-1"

  cidr            = "10.1.0.0/16"
  azs             = slice(data.aws_availability_zones.available.names, 0, 3)
  public_subnets  = ["10.1.101.0/24", "10.1.102.0/24", "10.1.103.0/24"]

  enable_nat_gateway   = false
  single_nat_gateway   = true
  enable_dns_hostnames = true
}

module "vpc-2" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "5.16.0"
  name    = "group1-vpc-2"

  cidr            = "10.2.0.0/16"
  azs             = slice(data.aws_availability_zones.available.names, 0, 3)
  public_subnets  = ["10.2.101.0/24", "10.2.102.0/24", "10.2.103.0/24"]

  enable_nat_gateway   = false
  single_nat_gateway   = true
  enable_dns_hostnames = true
}

locals {
  name_prefix = "group1"
}

data "aws_availability_zones" "available" {
  state = "available"
}


# Security groups

resource "aws_security_group" "sg_vpc_1" {
  name        = "group1-sg-vpc-1"
  description = "Security group for VPC 1"
  #vpc_id      = var.vpc_id_1
  vpc_id      = "vpc-0941974af902677af"
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
}

egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "sg_vpc_2" {
  name        = "group1-sg-vpc-2"
  description = "Security group for VPC 2"
  #vpc_id      = var.vpc_id_2
  vpc_id      ="vpc-08c48a150e68216da"

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
}

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_instance" "group1-ec2-1" {
  ami           = "ami-04c913012f8977029"
  instance_type = "t2.micro"
  vpc_security_group_ids = [aws_security_group.sg_vpc_1.id]
   #subnet_id     = var.subnet_id_2
   subnet_id     = "subnet-0b7a8a48f865e42c7"
  associate_public_ip_address = true
}

resource "aws_instance" "group1-ec2-2" {
  ami           = "ami-04c913012f8977029"
  instance_type = "t2.micro"
  vpc_security_group_ids = [aws_security_group.sg_vpc_2.id]
  #subnet_id     = var.subnet_id_2
  subnet_id     = "subnet-01b73b85331985e9d"
  associate_public_ip_address = true
  }

data "aws_subnets" "subnet_id_1" {
  filter {
    name   = "vpc-id"
    values = [var.vpc_id_1]
  }
  filter {
    name   = "tag:Name"
    values = ["public-*"]
  }
}
data "aws_subnets" "subnet_id_2" {
  filter {
    name   = "vpc-id"
    values = [var.vpc_id_2]
  }
  filter {
    name   = "tag:Name"
    values = ["public-*"]
  }
}



/*

Rough workings

resource "aws_security_group" "allow_ssh" {
  name_prefix = "group1-sg"
  description = "Allow SSH inbound"
  vpc_id      = var.vpc_id #VPC ID (Same VPC as your EC2 subnet above), e.g. vpc-xxxxxxxxxxx
  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_vpc_security_group_ingress_rule" "allow_tls_ipv4" {
  security_group_id = aws_security_group.allow_ssh.id
  cidr_ipv4         = "0.0.0.0/0"  
  from_port         = 22
  ip_protocol       = "tcp"
  to_port           = 22
}


resource "aws_security_group" "alb" {
  name_prefix = "alb"
  description = "Allow web inbound traffic and all outbound traffic through the ALB"
  vpc_id      = module.vpc.vpc_id

  tags = {
    Name = "alb"
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_vpc_security_group_ingress_rule" "allow_tls_ipv4" {
  security_group_id = aws_security_group.allow_ssh.id
  cidr_ipv4         = "0.0.0.0/0"  
  from_port         = 22
  ip_protocol       = "tcp"
  to_port           = 22
}


resource "aws_vpc_security_group_ingress_rule" "allow_https_ipv4" {
  security_group_id = aws_security_group.allow_ssh.id
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 443
  ip_protocol       = "tcp"
  to_port           = 443
}

resource "aws_vpc_security_group_ingress_rule" "allow_https_ipv6" {
  security_group_id = aws_security_group.allow_ssh.id
  cidr_ipv6         = "::/0"
  from_port         = 443
  ip_protocol       = "tcp"
  to_port           = 443
}

resource "aws_vpc_security_group_ingress_rule" "allow_http_ipv4" {
  security_group_id = aws_security_group.allow_ssh.id
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 80
  ip_protocol       = "tcp"
  to_port           = 80
}

resource "aws_vpc_security_group_ingress_rule" "allow_http_ipv6" {
  security_group_id = aws_security_group.allow_ssh.id
  cidr_ipv6         = "::/0"
  from_port         = 80
  ip_protocol       = "tcp"
  to_port           = 80
}

resource "aws_vpc_security_group_egress_rule" "allow_all_traffic_ipv4" {
  security_group_id = aws_security_group.allow_ssh.id
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1" # semantically equivalent to all ports
}

resource "aws_vpc_security_group_egress_rule" "allow_all_traffic_ipv6" {
  security_group_id = aws_security_group.allow_ssh.id
  cidr_ipv6         = "::/0"
  ip_protocol       = "-1" # semantically equivalent to all ports
}
*/