using System.ComponentModel.DataAnnotations;

namespace ProyectoSeguridadInformatica.Models
{
    public class DecryptViewModel
    {
        [Required]
        [Display(Name = "Texto cifrado (Base64)")]
        public string CipherText { get; set; } = string.Empty;

        [Display(Name = "Texto plano")]
        public string? PlainText { get; set; }
    }
}


