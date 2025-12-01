using ProyectoSeguridadInformatica.Models;

namespace ProyectoSeguridadInformatica.Services
{
    public interface IFirebaseUserService
    {
        Task<User?> GetUserByEmailAsync(string email);

        Task<User> CreateUserAsync(User user);
    }
}


