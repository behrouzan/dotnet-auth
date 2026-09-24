using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Sample.Api.Tests;

public sealed class SampleApiFactory : WebApplicationFactory<Program>
{
    private readonly string _databasePath = Path.Combine(
        Path.GetTempPath(),
        $"behrouzan-auth-sample-{Guid.NewGuid():N}.db");

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Testing");
        builder.UseSetting("https_port", "443");
        builder.ConfigureLogging(logging => logging.ClearProviders());
        builder.ConfigureServices(services => services
            .AddDataProtection()
            .UseEphemeralDataProtectionProvider());
        builder.ConfigureServices(services => services.Configure<IdentityOptions>(
            options => options.SignIn.RequireConfirmedEmail = true));
        builder.UseSetting(
            "ConnectionStrings:DefaultConnection",
            $"Data Source={_databasePath}");
        builder.UseSetting("TokenAuthentication:Issuer", "Sample.Api.Tests");
        builder.UseSetting(
            "TokenAuthentication:Audience",
            "Sample.Api.Tests.Client");
        builder.UseSetting("TokenAuthentication:Algorithm", "HS256");
        builder.UseSetting(
            "TokenAuthentication:AccessTokenLifetime",
            "00:15:00");
        builder.UseSetting(
            "TokenAuthentication:RefreshTokenLifetime",
            "30.00:00:00");
        builder.UseSetting(
            "TokenAuthentication:SigningKey",
            Convert.ToBase64String(
                Enumerable.Range(1, 32).Select(value => (byte)value).ToArray()));
    }

    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        SqliteConnection.ClearAllPools();

        if (File.Exists(_databasePath))
        {
            File.Delete(_databasePath);
        }
    }
}
