using ProyectoSeguridadInformatica.Models;
using ProyectoSeguridadInformatica.Services;

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

            builder.Services.AddHttpClient<IFirebaseUserService, FirebaseUserService>();
            builder.Services.AddSingleton<IRsaService, RsaService>();
            builder.Services.AddSession();

            var app = builder.Build();

            // Configure the HTTP request pipeline.
            if (!app.Environment.IsDevelopment())
            {
                app.UseExceptionHandler("/Home/Error");
            }
            app.UseStaticFiles();

            app.UseRouting();

            app.UseSession();
            app.UseAuthorization();

            app.MapControllerRoute(
                name: "default",
                pattern: "{controller=Home}/{action=Index}/{id?}");

            app.Run();
        }
    }
}
