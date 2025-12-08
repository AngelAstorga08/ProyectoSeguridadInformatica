using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.RateLimiting;
using ProyectoSeguridadInformatica.Middleware;
using ProyectoSeguridadInformatica.Models;
using ProyectoSeguridadInformatica.Services;
using Polly;
using System.Net;
using System.Net.Http;
using System.Threading.RateLimiting;
using IPNetwork = Microsoft.AspNetCore.HttpOverrides.IPNetwork;

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

            builder.Services.AddHttpClient<FirebaseAuthService>();

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
            builder.Services.AddSingleton<AesService>();
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
                static string IpKey(HttpContext ctx) =>
                    DeviceIdentifier.GetClientIp(ctx);

                static string FingerprintKey(HttpContext ctx)
                {
                    // Clave estable: fingerprint basado en IP + User-Agent (sin depender de cookies).
                    return DeviceIdentifier.GetFingerprint(ctx);
                }

                // 1. Política GLOBAL por IP (cap general)
                options.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(
                    httpContext => RateLimitPartition.GetFixedWindowLimiter(
                        partitionKey: IpKey(httpContext),
                        factory: _ => new FixedWindowRateLimiterOptions
                        {
                            PermitLimit = 300,                    // 300 peticiones
                            Window = TimeSpan.FromMinutes(1),     // por minuto por IP
                            QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
                            QueueLimit = 50                       // hasta 50 en cola, el resto 429 inmediato
                        }));

                // 2. Política más estricta para endpoints de login / registro (por fingerprint IP+UA)
                options.AddPolicy("auth-strict", httpContext =>
                    RateLimitPartition.GetTokenBucketLimiter(
                        partitionKey: FingerprintKey(httpContext),
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

            // Middleware global de excepciones (antes del resto del pipeline)
            app.UseMiddleware<GlobalExceptionMiddleware>();

            var forwardedOptions = new ForwardedHeadersOptions
            {
                ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto
            };

            var knownProxies = builder.Configuration
                .GetSection("ForwardedHeaders:KnownProxies")
                .Get<string[]>();
            if (knownProxies != null)
            {
                foreach (var proxy in knownProxies)
                {
                    if (IPAddress.TryParse(proxy, out var ip))
                    {
                        forwardedOptions.KnownProxies.Add(ip);
                    }
                }
            }

            var knownNetworks = builder.Configuration
                .GetSection("ForwardedHeaders:KnownNetworks")
                .Get<string[]>();
            if (knownNetworks != null)
            {
                foreach (var network in knownNetworks)
                {
                    var parts = network.Split('/', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
                    if (parts.Length == 2
                        && IPAddress.TryParse(parts[0], out var ip)
                        && int.TryParse(parts[1], out var prefixLength))
                    {
                        forwardedOptions.KnownNetworks.Add(new IPNetwork(ip, prefixLength));
                    }
                }
            }

            var forwardLimit = builder.Configuration.GetValue<int?>("ForwardedHeaders:ForwardLimit");
            if (forwardLimit.HasValue)
            {
                forwardedOptions.ForwardLimit = forwardLimit.Value;
            }

            // Si no se configuran proxies/redes (p. ej. Render con IPs dinámicas),
            // se confía en un único salto y se limpian restricciones para tomar la IP real.
            var hasConfiguredSources =
                (knownProxies?.Length ?? 0) > 0 ||
                (knownNetworks?.Length ?? 0) > 0;
            if (!hasConfiguredSources && !forwardLimit.HasValue)
            {
                forwardedOptions.KnownNetworks.Clear();
                forwardedOptions.KnownProxies.Clear();
                forwardedOptions.ForwardLimit = 1;
            }

            app.UseForwardedHeaders(forwardedOptions);

            // Log temporal para verificar IP real y cabeceras reenviadas antes del rate limiter.
            app.Use(async (context, next) =>
            {
                var remoteIp = DeviceIdentifier.GetClientIp(context);
                var xff = context.Request.Headers["X-Forwarded-For"].ToString();
                context.RequestServices
                    .GetRequiredService<ILogger<Program>>()
                    .LogInformation("Client IP={RemoteIp} XFF={XFF}", remoteIp, xff);
                await next();
            });

            // Configure the HTTP request pipeline.
            if (!app.Environment.IsDevelopment())
            {
                app.UseExceptionHandler("/Home/Error");
            }
            app.UseStaticFiles();

            app.UseRouting();
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
