using Behrouzan.Auth.AspNetCore.Authentication;
using Behrouzan.Auth.AspNetCore.DependencyInjection;
using Behrouzan.Auth.DependencyInjection;
using Behrouzan.Auth.EntityFrameworkCore.DependencyInjection;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Sample.Api.Data;
using Sample.Api.Endpoints;
using Sample.Api.Identity;
using Sample.Api.TokenAuthentication;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
builder.Services.AddAntiforgery(options =>
{
    options.HeaderName = "X-CSRF-TOKEN";

    if (!builder.Environment.IsDevelopment())
    {
        options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    }
});

builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlite(
        builder.Configuration.GetConnectionString("DefaultConnection")));

builder.Services
    .AddIdentity<ApplicationUser, ApplicationRole>()
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddDefaultTokenProviders();

var tokenOptions = SampleTokenAuthenticationOptions.FromConfiguration(
    builder.Configuration.GetSection(
        SampleTokenAuthenticationOptions.SectionName));

builder.Services
    .AddAuthentication()
    .AddJwtBearer(
        JwtBearerDefaults.AuthenticationScheme,
        options =>
        {
            options.MapInboundClaims = false;
            options.TokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidIssuer = tokenOptions.Issuer,
                ValidateAudience = true,
                ValidAudience = tokenOptions.Audience,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = tokenOptions.SigningKey,
                ValidAlgorithms = [tokenOptions.Algorithm],
                ValidateLifetime = true,
                ClockSkew = TimeSpan.Zero,
                NameClaimType = "sub"
            };
        });

builder.Services.ConfigureApplicationCookie(options =>
{
    options.Events.OnRedirectToLogin = context =>
    {
        context.Response.StatusCode = StatusCodes.Status401Unauthorized;
        return Task.CompletedTask;
    };

    options.Events.OnRedirectToAccessDenied = context =>
    {
        context.Response.StatusCode = StatusCodes.Status403Forbidden;
        return Task.CompletedTask;
    };
});

builder.Services.AddAuthorization();
builder.Services.AddBehrouzanAuth();
builder.Services.AddRefreshTokens(options =>
    options.Lifetime = tokenOptions.RefreshTokenLifetime);
builder.Services.AddBehrouzanAuthAspNetCore<Guid>();
builder.Services.AddBehrouzanAuthEntityFrameworkCore<
    ApplicationDbContext,
    ApplicationUser,
    ApplicationRole,
    Guid>();
builder.Services.AddBehrouzanPasswordSignIn<ApplicationUser>(options =>
{
    options.AllowedIdentifiers =
        SignInIdentifier.UserName |
        SignInIdentifier.Email |
        SignInIdentifier.PhoneNumber;
});
builder.Services.AddBehrouzanAccessTokens(options =>
{
    options.Issuer = tokenOptions.Issuer;
    options.Audience = tokenOptions.Audience;
    options.Lifetime = tokenOptions.AccessTokenLifetime;
});
builder.Services.AddBehrouzanIdentityTokenLogin<ApplicationUser, Guid>();
builder.Services.AddBehrouzanTokenRefresh<ApplicationUser, Guid>();
builder.Services.AddSingleton<IAccessTokenSigningCredentialsProvider>(
    new SampleAccessTokenSigningCredentialsProvider(
        tokenOptions.SigningKey,
        tokenOptions.Algorithm));
builder.Services.AddScoped<
    IRefreshTokenUserResolver<ApplicationUser, Guid>,
    ApplicationRefreshTokenUserResolver>();

var app = builder.Build();

await using (var scope = app.Services.CreateAsyncScope())
{
    var dbContext =
        scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();

    await dbContext.Database.EnsureCreatedAsync();

    if (app.Environment.IsDevelopment())
    {
        var userManager =
            scope.ServiceProvider.GetRequiredService<
                UserManager<ApplicationUser>>();

        await DevelopmentUserSeeder.SeedAsync(userManager);
    }
}

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();

app.MapAuthEndpoints();

var summaries = new[]
{
    "Freezing", "Bracing", "Chilly", "Cool", "Mild", "Warm", "Balmy", "Hot", "Sweltering", "Scorching"
};

app.MapGet("/weatherforecast", () =>
{
    var forecast =  Enumerable.Range(1, 5).Select(index =>
        new WeatherForecast
        (
            DateOnly.FromDateTime(DateTime.Now.AddDays(index)),
            Random.Shared.Next(-20, 55),
            summaries[Random.Shared.Next(summaries.Length)]
        ))
        .ToArray();
    return forecast;
})
.WithName("GetWeatherForecast")
.WithOpenApi();

app.Run();

record WeatherForecast(DateOnly Date, int TemperatureC, string? Summary)
{
    public int TemperatureF => 32 + (int)(TemperatureC / 0.5556);
}

public partial class Program;
