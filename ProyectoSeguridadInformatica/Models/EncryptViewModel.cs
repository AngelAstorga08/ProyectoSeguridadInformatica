using System.ComponentModel.DataAnnotations;

namespace ProyectoSeguridadInformatica.Models
{
    public class EncryptViewModel
    {
        [Required]
        [Display(Name = "Texto plano")]
        public string PlainText { get; set; } = string.Empty;

        [Display(Name = "Texto cifrado (Base64)")]
        public string? CipherText { get; set; }
    }
}


