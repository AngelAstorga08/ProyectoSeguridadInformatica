using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Polly;
using Microsoft.AspNetCore.DataProtection;

namespace ProyectoSeguridadInformatica.Services
{
    /// <summary>
    /// DelegatingHandler que añade el identificador de dispositivo a las peticiones salientes.
    /// </summary>
public class DeviceIdHandler : DelegatingHandler
{
    private readonly IHttpContextAccessor _accessor;
    private readonly ILogger<DeviceIdHandler> _logger;
    private readonly IAsyncPolicy<HttpResponseMessage> _policy;

    public DeviceIdHandler(
        IHttpContextAccessor accessor,
        ILogger<DeviceIdHandler> logger,
        IAsyncPolicy<HttpResponseMessage> policy) // ← inyectada!
    {
        _accessor = accessor;
        _logger = logger;
        _policy = policy;
    }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct)
    {
        var deviceId = DeviceIdentifier.GetOrCreateDeviceId(_accessor.HttpContext);

        if (!string.IsNullOrEmpty(deviceId) && !request.Headers.Contains("X-Device-Id"))
            request.Headers.Add("X-Device-Id", deviceId);

        return await _policy.ExecuteAsync(
            ctx => base.SendAsync(request, ctx),
            ct);
    }
}
}


