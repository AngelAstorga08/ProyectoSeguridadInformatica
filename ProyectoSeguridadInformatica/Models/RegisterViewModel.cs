using System.ComponentModel.DataAnnotations;
using System.ComponentModel;

namespace ProyectoSeguridadInformatica.Models
{
    public class RegisterViewModel
    {
        [Required]
        [EmailAddress]
        [DisplayName("Correo electrónico")]
        public string Email { get; set; } = string.Empty;

        [Required]
        [DataType(DataType.Password)]
        [MinLength(8, ErrorMessage = "La contraseña debe tener al menos 8 caracteres.")]
        [MaxLength(100, ErrorMessage = "La contraseña no puede tener más de 100 caracteres.")]
        [RegularExpression(
            @"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$",
            ErrorMessage = "La contraseña debe tener al menos 8 caracteres, una letra mayúscula, una letra minúscula, un número y un carácter especial.")]
        [DisplayName("Contraseña")]
        public string Password { get; set; } = string.Empty;

        [Required]
        [DataType(DataType.Password)]
        [Compare("Password", ErrorMessage = "Las contraseñas no coinciden.")]
        [DisplayName("Confirmar contraseña")]
        public string ConfirmPassword { get; set; } = string.Empty;
    }
}


