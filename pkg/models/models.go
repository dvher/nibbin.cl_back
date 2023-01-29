package models

type LoginRequest struct {
	Email string `json:"email" binding:"required,email"`
}

type OTPRequest struct {
	OTP int64 `json:"otp" binding:"required"`
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
