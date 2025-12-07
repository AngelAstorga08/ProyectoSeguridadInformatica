using System.Net.Http.Json;
using Microsoft.Extensions.Options;
using ProyectoSeguridadInformatica.Models;
using System.Web;
using System.Text.Json;



namespace ProyectoSeguridadInformatica.Services
{
    public class FirebaseUserService
    {
        private readonly HttpClient _http;
        private readonly FirebaseOptions _opt;

        public FirebaseUserService(HttpClient http, IOptions<FirebaseOptions> opt)
        {
            _http = http;
            _opt = opt.Value;
        }

        private string Url(string path, string token)
            => $"{_opt.BaseUrl}{path}.json?auth={token}";

        public async Task CreateUserAsync(User user, string idToken)
        {
            var url = Url($"users/{user.Id}", idToken);
            var response = await _http.PutAsJsonAsync(url, user);

            var content = await response.Content.ReadAsStringAsync();
            Console.WriteLine("RTDB RESPONSE: " + content);  // <-- AGREGA ESTO

            response.EnsureSuccessStatusCode();
        }

        public async Task<User?> GetUserAsync(string uid, string idToken)
        {
            var url = Url($"users/{uid}", idToken);
            return await _http.GetFromJsonAsync<User>(url);
        }

        public async Task UpdateUserAsync(User user)
        {
            var url = $"{_options.BaseUrl}users/{user.Id}.json";
            if (!string.IsNullOrEmpty(_options.ApiKey))
            {
                url += $"?auth={_options.ApiKey}";
            }

            var response = await _httpClient.PutAsJsonAsync(url, user);
            response.EnsureSuccessStatusCode();
        }
    }
}


