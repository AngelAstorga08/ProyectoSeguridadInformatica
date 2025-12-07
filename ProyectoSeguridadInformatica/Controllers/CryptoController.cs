using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using ProyectoSeguridadInformatica.Models;
using ProyectoSeguridadInformatica.Services;

namespace ProyectoSeguridadInformatica.Controllers
{
    [Authorize]
    public class CryptoController : Controller
    {
        private readonly RsaService _rsaService;

        public CryptoController(RsaService rsaService)
        {
            _rsaService = rsaService;
        }

        [HttpGet]
        public IActionResult Encrypt()
        {
            return View(new EncryptViewModel());
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public IActionResult Encrypt(EncryptViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            model.CipherText = _rsaService.Encrypt(model.PlainText);
            return View(model);
        }

        [HttpGet]
        public IActionResult Decrypt()
        {
            return View(new DecryptViewModel());
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public IActionResult Decrypt(DecryptViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            try
            {
                model.PlainText = _rsaService.Decrypt(model.CipherText);
            }
            catch
            {
                ModelState.AddModelError(string.Empty, "No se pudo desencriptar el texto. Verifica que sea un Base64 válido generado por esta aplicación.");
            }

            return View(model);
        }
    }
}


