package models

type LoginRequest struct {
	Email string `json:"email" binding:"required,email"`
}

type OTPRequest struct {
	OTP   string `json:"otp"   binding:"required"`
	Email string `json:"email" binding:"required,email"`
}

type RegisterRequest struct {
	Nombre     string `json:"nombre"     binding:"required"`
	Apellido   string `json:"apellido"   binding:"required"`
	Email      string `json:"email"      binding:"required,email"`
	User       string `json:"user"       binding:"required"`
	Direccion  string `json:"direccion"  binding:"required"`
	Telefono   string `json:"telefono"   binding:"required"`
	Nacimiento string `json:"nacimiento" binding:"required"`
}

type LoginAdminRequest struct {
	User     string `json:"user"     binding:"required"`
	Password string `json:"password" binding:"required"`
}

type RegisterAdminRequest struct {
	Email    string `json:"email"    binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

type SearchRequest struct {
	Search string `json:"search" binding:"required"`
}

type Producto struct {
	ID          int     `json:"id"`
	Nombre      string  `json:"nombre"      binding:"required"`
	Marca       string  `json:"marca"       binding:"required"`
	Descripcion string  `json:"descripcion" binding:"required"`
	Descuento   float32 `json:"descuento"   binding:"required"`
	Stock       int     `json:"stock"       binding:"required"`
	Imagen      string  `json:"imagen"      binding:"required"`
	IsFavorite  bool    `json:"isfavorite"`
}

type DescProducto struct {
	ID          int     `json:"id"`
	Nombre      string  `json:"nombre"      binding:"required"`
	Marca       string  `json:"marca"       binding:"required"`
	Descripcion string  `json:"descripcion" binding:"required"`
	Precio      int     `json:"precio"      binding:"required"`
	Descuento   float32 `json:"descuento"   binding:"required"`
	Stock       int     `json:"stock"       binding:"required"`
	Imagen      string  `json:"imagen"      binding:"required"`
	IsFavorite  bool    `json:"isfavorite"`
}

type Favorito struct {
	ID         int `json:"id"`
	IDUsuario  int `json:"idUsuario"`
	IDProducto int `json:"idProducto" binding:"required"`
}
