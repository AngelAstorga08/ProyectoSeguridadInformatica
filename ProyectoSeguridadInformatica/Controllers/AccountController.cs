using Microsoft.AspNetCore.Mvc;
using ProyectoSeguridadInformatica.Models;
using ProyectoSeguridadInformatica.Services;

namespace ProyectoSeguridadInformatica.Controllers
{
    public class AccountController : Controller
    {
        private readonly IFirebaseUserService _firebaseUserService;
        public AccountController(IFirebaseUserService firebaseUserService)
        {
            _firebaseUserService = firebaseUserService;
        }

        [HttpGet]
        public IActionResult Register()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Register(RegisterViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            var existing = await _firebaseUserService.GetUserByEmailAsync(model.Email);
            if (existing != null)
            {
                ModelState.AddModelError(string.Empty, "Ya existe un usuario con ese correo.");
                return View(model);
            }

            var (hash, salt) = PasswordHasher.HashPassword(model.Password);

            var user = new User
            {
                Email = model.Email,
                PasswordHash = hash,
                PasswordSalt = salt
            };

            await _firebaseUserService.CreateUserAsync(user);
            SignInUser(user);

            return RedirectToAction("Index", "Home");
        }

        [HttpGet]
        public IActionResult Login(string? returnUrl = null)
        {
            return View(new LoginViewModel { ReturnUrl = returnUrl });
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            var user = await _firebaseUserService.GetUserByEmailAsync(model.Email);
            if (user == null ||
                !PasswordHasher.VerifyPassword(model.Password, user.PasswordHash, user.PasswordSalt))
            {
                ModelState.AddModelError(string.Empty, "Credenciales inválidas.");
                return View(model);
            }

            SignInUser(user);

            if (!string.IsNullOrEmpty(model.ReturnUrl) && Url.IsLocalUrl(model.ReturnUrl))
            {
                return Redirect(model.ReturnUrl);
            }

            return RedirectToAction("Index", "Home");
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public IActionResult Logout()
        {
            HttpContext.Session.Clear();
            return RedirectToAction("Index", "Home");
        }

        private void SignInUser(User user)
        {
            HttpContext.Session.SetString("UserId", user.Id);
            HttpContext.Session.SetString("UserEmail", user.Email);
        }
    }
}


