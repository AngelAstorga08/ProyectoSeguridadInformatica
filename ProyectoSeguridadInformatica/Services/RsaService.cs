using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;
using ProyectoSeguridadInformatica.Models;

namespace ProyectoSeguridadInformatica.Services
{
    public class RsaService : IRsaService, IDisposable
    {
        private readonly RSA _rsa;

        public RsaService(IOptionsMonitor<RsaOptions> optionsMonitor)
        {
            _rsa = RSA.Create();
            _rsa.KeySize = optionsMonitor.CurrentValue.KeySize;
        }

        public string Encrypt(string plainText)
        {
            var data = Encoding.UTF8.GetBytes(plainText);
            var encrypted = _rsa.Encrypt(data, RSAEncryptionPadding.OaepSHA256);
            return Convert.ToBase64String(encrypted);
        }

        public string Decrypt(string base64CipherText)
        {
            var data = Convert.FromBase64String(base64CipherText);
            var decrypted = _rsa.Decrypt(data, RSAEncryptionPadding.OaepSHA256);
            return Encoding.UTF8.GetString(decrypted);
        }

        public void Dispose()
        {
            _rsa.Dispose();
        }
    }
}


