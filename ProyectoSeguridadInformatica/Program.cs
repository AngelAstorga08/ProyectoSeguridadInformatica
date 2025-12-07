using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.RateLimiting;
using ProyectoSeguridadInformatica.Models;
using ProyectoSeguridadInformatica.Services;
using Polly;
using System.Net;
using System.Net.Http;
using System.Threading.RateLimiting;

namespace ProyectoSeguridadInformatica
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            // Add services to the container.
            builder.Services.AddControllersWithViews();
            builder.Services.Configure<FirebaseOptions>(builder.Configuration.GetSection("Firebase"));
            builder.Services.Configure<RsaOptions>(builder.Configuration.GetSection("Rsa"));

            builder.Services.AddHttpClient<FirebaseAuthService>();
            builder.Services.AddHttpClient<FirebaseUserService>();

            builder.Services.AddHttpContextAccessor();
            builder.Services.AddTransient<DeviceIdHandler>();

            // HttpClient hacia Firebase con políticas de resiliencia basadas en Polly
            builder.Services.AddHttpClient<FirebaseUserService>()
                .AddHttpMessageHandler<DeviceIdHandler>();


            builder.Services.AddSingleton<IAsyncPolicy<HttpResponseMessage>>(sp =>
            {
                var logger = sp.GetRequiredService<ILogger<DeviceIdHandler>>();

                var retry = Policy<HttpResponseMessage>
                    .Handle<HttpRequestException>()
                    .OrResult(r => (int)r.StatusCode >= 500 || r.StatusCode == HttpStatusCode.TooManyRequests)
                    .WaitAndRetryAsync(
                        3,
                        attempt => TimeSpan.FromMilliseconds(200 * Math.Pow(2, attempt - 1)),
                        onRetry: (outcome, timespan, attempt, ctx) =>
                            logger.LogWarning("Firebase retry {Attempt} after {Delay}ms", attempt, timespan.TotalMilliseconds));

                var cb = Policy<HttpResponseMessage>
                    .Handle<HttpRequestException>()
                    .OrResult(r => (int)r.StatusCode >= 500)
                    .CircuitBreakerAsync(5, TimeSpan.FromSeconds(30),
                        onBreak: (_, delay) => logger.LogError("Circuit OPEN for {Delay}s", delay.TotalSeconds),
                        onReset: () => logger.LogInformation("Circuit CLOSED"));

                // Política combinada: primero reintentos, luego circuit breaker
                return Policy.WrapAsync(retry, cb);
            });
            builder.Services.AddDataProtection();
            builder.Services.AddMemoryCache();
            builder.Services.AddSingleton<RsaService>();
            builder.Services.AddSession(options =>
            {
                options.IdleTimeout = TimeSpan.FromMinutes(20);
                options.Cookie.HttpOnly = true;
                options.Cookie.IsEssential = true;
                options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
                options.Cookie.SameSite = SameSiteMode.Strict;
            });

            builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
                .AddCookie(options =>
                {
                    options.LoginPath = "/Account/Login";
                    options.AccessDeniedPath = "/Account/Login";
                    options.ExpireTimeSpan = TimeSpan.FromMinutes(20);
                    options.SlidingExpiration = true;
                    options.Cookie.HttpOnly = true;
                    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
                    options.Cookie.SameSite = SameSiteMode.Strict;
                });


            // ==================== RATE LIMITING NATIVO (.NET 8) ====================

            builder.Services.AddRateLimiter(options =>
            {
                // 1. Política GLOBAL por IP (por defecto para todos los endpoints)
                options.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, IPAddress>(
                    httpContext => RateLimitPartition.GetFixedWindowLimiter(
                        partitionKey: httpContext.Connection.RemoteIpAddress ?? IPAddress.Loopback,
                        factory: _ => new FixedWindowRateLimiterOptions
                        {
                            PermitLimit = 300,                    // 300 peticiones
                            Window = TimeSpan.FromMinutes(1),     // por minuto por IP
                            QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                            QueueLimit = 50                       // hasta 50 en cola, el resto 429 inmediato
                        }));

                // 2. Política más estricta para endpoints de login / registro
                options.AddPolicy("auth-strict", httpContext =>
                    RateLimitPartition.GetTokenBucketLimiter(
                        partitionKey: httpContext.Connection.RemoteIpAddress ?? IPAddress.Loopback,
                        factory: _ => new TokenBucketRateLimiterOptions
                        {
                            TokenLimit = 20,                          // capacidad máxima del bucket
                            TokensPerPeriod = 5,                      // recarga 5 tokens
                            ReplenishmentPeriod = TimeSpan.FromSeconds(10), // cada 10 segundos
                            AutoReplenishment = true,
                            QueueLimit = 0                            // sin cola → rechaza inmediatamente si excede
                        }));

                // Respuesta personalizada cuando se rechaza
                options.OnRejected = async (context, token) =>
                {
                    context.HttpContext.Response.StatusCode = 429;
                    context.HttpContext.Response.ContentType = "application/json";

                    if (context.Lease.TryGetMetadata(MetadataName.RetryAfter, out var retryAfter))
                        context.HttpContext.Response.Headers.RetryAfter = retryAfter.TotalSeconds.ToString("0");

                    await context.HttpContext.Response.WriteAsync(
                        "{\"error\": \"Demasiadas peticiones. Intenta de nuevo más tarde.\"}", token);
                };
            });
            var app = builder.Build();

            // Configure the HTTP request pipeline.
            if (!app.Environment.IsDevelopment())
            {
                app.UseExceptionHandler("/Home/Error");
            }
            app.UseStaticFiles();

            app.UseRouting();

            app.UseDeveloperExceptionPage();


            // Middleware para asegurar cookie de dispositivo en cada petición
            app.Use(async (context, next) =>
            {
                DeviceIdentifier.GetOrCreateDeviceId(context);
                await next();
            });
            app.UseRateLimiter();
            app.UseSession();
            app.UseAuthentication();
            app.UseAuthorization();

            app.MapControllerRoute(
                name: "default",
                pattern: "{controller=Home}/{action=Index}/{id?}");

            app.Run();
        }
    }
}
