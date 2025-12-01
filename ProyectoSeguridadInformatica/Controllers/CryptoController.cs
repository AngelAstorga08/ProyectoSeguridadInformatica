using Microsoft.AspNetCore.Mvc;
using ProyectoSeguridadInformatica.Models;
using ProyectoSeguridadInformatica.Services;

namespace ProyectoSeguridadInformatica.Controllers
{
    public class CryptoController : Controller
    {
        private readonly IRsaService _rsaService;

        public CryptoController(IRsaService rsaService)
        {
            _rsaService = rsaService;
        }

        [HttpGet]
        public IActionResult Encrypt()
        {
            if (!IsAuthenticated())
            {
                return RedirectToLogin();
            }

            return View(new EncryptViewModel());
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public IActionResult Encrypt(EncryptViewModel model)
        {
            if (!IsAuthenticated())
            {
                return RedirectToLogin();
            }

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
            if (!IsAuthenticated())
            {
                return RedirectToLogin();
            }

            return View(new DecryptViewModel());
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public IActionResult Decrypt(DecryptViewModel model)
        {
            if (!IsAuthenticated())
            {
                return RedirectToLogin();
            }

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

        private bool IsAuthenticated()
        {
            return HttpContext.Session.GetString("UserId") != null;
        }

        private IActionResult RedirectToLogin()
        {
            var returnUrl = Url.Action(
                action: ControllerContext.ActionDescriptor.ActionName,
                controller: ControllerContext.ActionDescriptor.ControllerName);

            return RedirectToAction("Login", "Account", new { returnUrl });
        }
    }
}


