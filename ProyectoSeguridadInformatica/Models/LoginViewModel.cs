using System.ComponentModel.DataAnnotations;
using System.ComponentModel;

namespace ProyectoSeguridadInformatica.Models
{
    public class LoginViewModel
    {
        [Required]
        [EmailAddress]
        [DisplayName("Correo electrónico")]
        public string Email { get; set; } = string.Empty;

        [Required]
        [DataType(DataType.Password)]
        [DisplayName("Contraseña")]
        public string Password { get; set; } = string.Empty;

        public string? ReturnUrl { get; set; }
    }
}


