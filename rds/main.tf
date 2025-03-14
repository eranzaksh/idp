# Provider Configuration
provider "aws" {
  region = var.aws_region
}


# Get default VPC
data "aws_vpc" "default" {
  default = true
}

# Get default subnets
data "aws_subnets" "default" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.default.id]
  }
}

# Subnet Group for RDS
resource "aws_db_subnet_group" "idp_db_subnet_group" {
  name       = "idp-db-subnet-group"
  subnet_ids = slice(tolist(data.aws_subnets.default.ids), 0, 2)

  tags = {
    Name = "IDP DB Subnet Group"
  }
}

# RDS Instance
resource "aws_db_instance" "idp_db" {
  identifier              = "idp-db"
  allocated_storage       = 20
  storage_type            = "gp2"
  engine                  = "mysql"
  engine_version          = "8.0"
  instance_class          = "db.t4g.micro"
  db_name                 = var.db_name
  username                = var.db_username
  password                = var.db_password
  parameter_group_name    = "default.mysql8.0"
  vpc_security_group_ids  = ["sg-0066aa02b48a24a0b"]
  db_subnet_group_name    = aws_db_subnet_group.idp_db_subnet_group.name
  skip_final_snapshot     = true
  deletion_protection     = true
  publicly_accessible     = true
  
  tags = {
    Name = "idp-database"
  }
}

# Outputs
output "rds_endpoint" {
  description = "The connection endpoint for the RDS instance"
  value       = aws_db_instance.idp_db.endpoint
}

