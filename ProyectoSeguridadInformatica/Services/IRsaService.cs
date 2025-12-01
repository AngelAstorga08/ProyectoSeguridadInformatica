namespace ProyectoSeguridadInformatica.Services
{
    public interface IRsaService
    {
        string Encrypt(string plainText);

        string Decrypt(string base64CipherText);
    }
}


