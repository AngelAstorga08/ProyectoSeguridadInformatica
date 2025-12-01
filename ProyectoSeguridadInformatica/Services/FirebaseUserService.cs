using System.Net.Http.Json;
using Microsoft.Extensions.Options;
using ProyectoSeguridadInformatica.Models;

namespace ProyectoSeguridadInformatica.Services
{
    public class FirebaseUserService : IFirebaseUserService
    {
        private readonly HttpClient _httpClient;
        private readonly FirebaseOptions _options;

        public FirebaseUserService(HttpClient httpClient, IOptions<FirebaseOptions> options)
        {
            _httpClient = httpClient;
            _options = options.Value;
        }

        public async Task<User?> GetUserByEmailAsync(string email)
        {
            if (string.IsNullOrWhiteSpace(email))
            {
                return null;
            }

            var url = $"{_options.BaseUrl}users.json";
            if (!string.IsNullOrEmpty(_options.ApiKey))
            {
                url += $"?auth={_options.ApiKey}";
            }

            var response = await _httpClient.GetAsync(url);
            if (!response.IsSuccessStatusCode)
            {
                return null;
            }

            var data = await response.Content.ReadFromJsonAsync<Dictionary<string, User>>();
            if (data == null)
            {
                return null;
            }

            return data.Values.FirstOrDefault(u =>
                u.Email.Equals(email, StringComparison.OrdinalIgnoreCase));
        }

        public async Task<User> CreateUserAsync(User user)
        {
            var url = $"{_options.BaseUrl}users/{user.Id}.json";
            if (!string.IsNullOrEmpty(_options.ApiKey))
            {
                url += $"?auth={_options.ApiKey}";
            }

            var response = await _httpClient.PutAsJsonAsync(url, user);
            response.EnsureSuccessStatusCode();

            return user;
        }
    }
}


