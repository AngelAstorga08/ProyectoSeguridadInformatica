using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using ProyectoSeguridadInformatica.Models;
using ProyectoSeguridadInformatica.Services;
using System.Security.Cryptography;
using System.Text;
using System.Security.Claims;
using BC = BCrypt.Net.BCrypt;
using Microsoft.Extensions.Caching.Memory;

namespace ProyectoSeguridadInformatica.Controllers
{
    public class AccountController : Controller
    {
        private readonly FirebaseUserService _firebaseUserService;
        private readonly ILogger<AccountController> _logger;
        private readonly IMemoryCache _cache;
        public AccountController(FirebaseUserService firebaseUserService, ILogger<AccountController> logger, IMemoryCache cache)
        private readonly FirebaseAuthService _authService;
        private readonly FirebaseUserService _userService;

        public AccountController(
            FirebaseAuthService authService,
            FirebaseUserService userService)
        {
            _firebaseUserService = firebaseUserService;
            _logger = logger;
            _cache = cache;
            _authService = authService;
            _userService = userService;
        }

        // ==========================
        //     VISTA REGISTRO
        // ==========================
        [HttpGet]
        public IActionResult Register()
        {
            return View();
        }

        [HttpPost]
        // ==========================
        //     POST REGISTRO
        // ==========================
        [HttpPost]
        [ValidateAntiForgeryToken]
        [EnableRateLimiting("auth-strict")]
        public async Task<IActionResult> Register(RegisterViewModel model)
        {
            if (!ModelState.IsValid)
                return View(model);

            var auth = await _authService.RegisterAsync(model.Email, model.Password);

            if (auth == null)
            {
                ModelState.AddModelError("", "No se pudo registrar el usuario.");
                return View(model);
            }

            var user = new User
            {
                Id = auth.LocalId,
                Email = auth.Email
            };

            await _firebaseUserService.CreateUserAsync(user);
            await SignInUserAsync(user);

            return RedirectToAction("Index", "Home");
        }

        // ==========================
        //     VISTA LOGIN
        // ==========================
        [HttpGet]
        public IActionResult Login(string? returnUrl = null)
        {
            if (!string.IsNullOrEmpty(returnUrl) && returnUrl.StartsWith("/Crypto", StringComparison.OrdinalIgnoreCase))
            {
                ModelState.AddModelError(string.Empty, "Debe iniciar sesión para acceder a esta funcionalidad.");
            }

            return View(new LoginViewModel { ReturnUrl = returnUrl });
        }

        // ==========================
        //     POST LOGIN
        // ==========================
        [HttpPost]
        [ValidateAntiForgeryToken]
        [EnableRateLimiting("auth-strict")]
        public async Task<IActionResult> Login(LoginViewModel model)
        {
            // 1. Generamos/obtenemos el DeviceId desde el principio
            var deviceId = DeviceIdentifier.GetOrCreateDeviceId(HttpContext);

            if (!ModelState.IsValid)
                return View(model);

            var auth = await _authService.LoginAsync(model.Email, model.Password);

            // 2. Obtenemos IP y email para el contador de intentos
            var ip = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
            var cacheKey = $"login_attempts:{model.Email}:{ip}";

            // 3. ¿Ya superó los 5 intentos?
            if (_cache.TryGetValue(cacheKey, out int attempts) && attempts >= 5)
            {
                _logger.LogWarning("Bloqueo por demasiados intentos. Email={Email}, IP={IP}, DeviceId={DeviceId}",
                    model.Email, ip, deviceId);

                ModelState.AddModelError(string.Empty, "Demasiados intentos fallidos. Espera 15 minutos.");
                return View(model);
            }

            // 4. Lógica normal de login
            var user = await _firebaseUserService.GetUserByEmailAsync(model.Email);

            if (user == null || !BC.EnhancedVerify(model.Password, user.PasswordHash))
            {
                // LOGIN FALLIDO → incrementamos contador
                attempts = _cache.GetOrCreate(cacheKey, entry =>
                {
                    entry.AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(15);
                    return 0;
                });

                var newAttempts = attempts + 1;
                _cache.Set(cacheKey, newAttempts, TimeSpan.FromMinutes(15));

                _logger.LogWarning(
                    "Intento de login fallido ({Attempt}/{Max}). Email={Email}, DeviceId={DeviceId}, IP={IP}",
                    newAttempts, 5, model.Email, deviceId, ip);

                ModelState.AddModelError(string.Empty,
                    newAttempts >= 5
                        ? "Demasiados intentos fallidos. Espera 15 minutos."
                        : "Credenciales inválidas.");

                return View(model);
            }

            // LOGIN EXITOSO → borramos el contador
            _cache.Remove(cacheKey);

            _logger.LogInformation("Login correcto. UserId={UserId}, Email={Email}, DeviceId={DeviceId}, IP={IP}",
                user.Id, model.Email, deviceId, ip);

            await SignInUserAsync(user);

            if (!string.IsNullOrEmpty(model.ReturnUrl) && Url.IsLocalUrl(model.ReturnUrl))
                return Redirect(model.ReturnUrl);

            return RedirectToAction("Index", "Home");
        }
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Logout()
        {
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            HttpContext.Session.Clear();
            Response.Cookies.Delete(".AspNetCore.Session");
            return RedirectToAction("Index", "Home");
        }

        [HttpGet]
        public IActionResult CheckAuth()
        {
            var isAuthenticated = HttpContext.Session.GetString("UserId") != null;
            return Json(new { isAuthenticated });
        }



        private async Task SignInUserAsync(User user)
        {
            // Renovar sesión para evitar fijación
            HttpContext.Session.Clear();

            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.NameIdentifier, user.Id),
                new Claim(ClaimTypes.Email, user.Email),
                new Claim(ClaimTypes.Name, user.Email)
            };

            var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
            var principal = new ClaimsPrincipal(identity);

            await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, principal);

            HttpContext.Session.SetString("UserId", user.Id);
            HttpContext.Session.SetString("UserEmail", user.Email);
            HttpContext.Session.SetString("SessionCreatedAt", DateTime.UtcNow.ToString("O"));
            HttpContext.Session.SetString("UserId", auth.LocalId);
            HttpContext.Session.SetString("UserEmail", auth.Email);
            HttpContext.Session.SetString("IdToken", auth.IdToken);
            HttpContext.Session.SetString("RefreshToken", auth.RefreshToken);
        }
    }
}


