using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using ProyectoSeguridadInformatica.Models;
using ProyectoSeguridadInformatica.Services;
using System.Security.Claims;
using Microsoft.Extensions.Caching.Memory;

namespace ProyectoSeguridadInformatica.Controllers
{
    public class AccountController : Controller
    {
        private readonly FirebaseUserService _firebaseUserService;
        private readonly ILogger<AccountController> _logger;
        private readonly IMemoryCache _cache;
        private readonly FirebaseAuthService _authService;
        private readonly FirebaseUserService _userService;

        public AccountController(
            FirebaseAuthService authService,
            FirebaseUserService userService,
            ILogger<AccountController> logger,
            IMemoryCache cache)
        {
            _authService = authService;
            _userService = userService;
            _logger = logger;
            _cache = cache;
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

            await _userService.CreateUserAsync(user, auth.IdToken);

            await SignInUserAsync(user, auth);


            return RedirectToAction("Index", "Home");
        }

        // ==========================
        //     VISTA LOGIN
        // ==========================
        [HttpGet]
        public IActionResult Login(string? returnUrl = null)
        {
            System.Console.WriteLine("ENTRE A LOGIN");

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
            System.Console.WriteLine("ENTRE A LOGIN POST");
            // 1. Generamos/obtenemos el DeviceId desde el principio
            var deviceId = DeviceIdentifier.GetOrCreateDeviceId(HttpContext);

            if (!ModelState.IsValid)
                return View(model);

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

            // 4. Llamamos a Firebase Auth
            var auth = await _authService.LoginAsync(model.Email, model.Password);

            // 5. Si las credenciales son inválidas (auth == null) → contamos como intento fallido
            if (auth == null)
            {
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

            // 6. Obtenemos el usuario desde la base de datos Firebase
            var user = await _userService.GetUserAsync(auth.LocalId, auth.IdToken);

            if (user == null)
            {
                // LOGIN FALLIDO → incrementamos contador igual que arriba
                attempts = _cache.GetOrCreate(cacheKey, entry =>
                {
                    entry.AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(15);
                    return 0;
                });

                var newAttempts = attempts + 1;
                _cache.Set(cacheKey, newAttempts, TimeSpan.FromMinutes(15));

                _logger.LogWarning(
                    "Intento de login fallido ({Attempt}/{Max}). Email={Email}, DeviceId={DeviceId}, IP={IP} (usuario no encontrado)",
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

            await SignInUserAsync(user, auth);

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
            var isAuthenticated = User?.Identity?.IsAuthenticated ?? false;
            return Json(new { isAuthenticated });
        }



        private async Task SignInUserAsync(User user, AuthResponse auth)
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

            HttpContext.Session.SetString("IdToken", auth.IdToken);
            HttpContext.Session.SetString("RefreshToken", auth.RefreshToken);
        }
    }
}


