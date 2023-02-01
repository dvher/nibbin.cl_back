package models

type LoginRequest struct {
	Email string `json:"email" binding:"required,email"`
}

type OTPRequest struct {
	OTP   string `json:"otp" binding:"required"`
	Email string `json:"email" binding:"required,email"`
}

type RegisterRequest struct {
	Nombre    string `json:"nombre"    binding:"required"`
	Apellido  string `json:"apellido"  binding:"required"`
	Email     string `json:"email"     binding:"required,email"`
	User      string `json:"user"      binding:"required"`
	Direccion string `json:"direccion" binding:"required"`
	Telefono  string `json:"telefono"  binding:"required"`
}

type LoginAdminRequest struct {
	User     string `json:"user"     binding:"required"`
	Password string `json:"password" binding:"required"`
}

type RegisterAdminRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

type SearchRequest struct {
	Search string `json:"search" binding:"required"`
}

type Producto struct {
	ID          int    `json:"id"`
	Nombre      string `json:"nombre"`
	Descripcion string `json:"descripcion"`
	Precio      int    `json:"precio"`
	Descuento   int    `json:"descuento"`
	Stock       int    `json:"stock"`
}
