variable "region" {
  description = "Región de AWS"
  type        = string
  default     = "sa-east-1"
}

variable "availability_zones" {
  description = "Zonas de disponibilidad"
  type        = list(string)
  default     = ["sa-east-1a", "sa-east-1b"]
}

variable "access_key" {
  description = "Clave de acceso de AWS"
  type        = string
}

variable "secret_key" {
  description = "Clave secreta de AWS"
  type        = string
}

variable "ami" {
  description = "Imagen de AWS"
  type        = string
  default     = "ami-065c72b3f381dab73"
}

variable "instance_type" {
  description = "Tipo de instancia EC2"
  type        = string
  default     = "t2.micro"
}

variable "jwt_secret" {
  description = "Secreto JWT"
  type        = string
}

variable "allowed_ssh_ips" {
  description = "Lista de CIDRs permitidos"
  type        = list(string)
  default     = ["18.228.70.32/29"]
}

variable "users_db_name" {
  description = "Nombre de la base de datos de Users"
  type        = string
  default     = "users_db"
}

variable "users_db_username" {
  description = "Usuario de la base de datos de Users"
  type        = string
  default     = "postgres"
}

variable "users_db_password" {
  description = "Contraseña de la base de datos de Users"
  type        = string
  default     = "foobarbaz"
}

variable "rooms_db_name" {
  description = "Nombre de la base de datos de Rooms"
  type        = string
  default     = "rooms_db"
}

variable "rooms_db_username" {
  description = "Usuario de la base de datos de Rooms"
  type        = string
  default     = "postgres"
}

variable "rooms_db_password" {
  description = "Contraseña de la base de datos de Rooms"
  type        = string
  default     = "foobarbaz"
}

variable "asks_db_name" {
  description = "Nombre de la base de datos de Asks"
  type        = string
  default     = "asks_db"
}

variable "asks_db_username" {
  description = "Usuario de la base de datos de Asks"
  type        = string
  default     = "postgres"
}

variable "asks_db_password" {
  description = "Contraseña de la base de datos de Asks"
  type        = string
  default     = "foobarbaz"
}

variable "bookings_db_name" {
  description = "Nombre de la base de datos de Bookings"
  type        = string
  default     = "bookings_db"
}

variable "bookings_db_username" {
  description = "Usuario de la base de datos de Bookings"
  type        = string
  default     = "postgres"
}

variable "bookings_db_password" {
  description = "Contraseña de la base de datos de Bookings"
  type        = string
  default     = "foobarbaz"
}

variable "email_account" {
  description = "Email de la cuenta de emails"
  type        = string
}

variable "email_password" {
  description = "Contraseña de la cuenta de emails"
  type        = string
}