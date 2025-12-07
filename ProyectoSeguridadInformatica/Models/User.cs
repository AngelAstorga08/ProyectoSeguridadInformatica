using System.ComponentModel.DataAnnotations;

namespace ProyectoSeguridadInformatica.Models
{
    public class User
    {
        public string Id { get; set; } = "";   // Se asigna con auth.LocalId

        [Required]
        [EmailAddress]
        public string Email { get; set; } = string.Empty;

        // <-- Esto NO se guarda en Firebase Realtime Database
        // Firebase Authentication se encarga del hash
        public string? DisplayName { get; set; }

        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

    }
}


