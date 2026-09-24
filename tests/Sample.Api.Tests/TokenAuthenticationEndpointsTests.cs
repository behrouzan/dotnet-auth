using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Sample.Api.Data;
using Sample.Api.Identity;
using Xunit;

namespace Sample.Api.Tests;

public sealed class TokenAuthenticationEndpointsTests
    : IClassFixture<SampleApiFactory>
{
    private const string Password = "Test123!";
    private readonly SampleApiFactory _factory;

    public TokenAuthenticationEndpointsTests(SampleApiFactory factory)
    {
        _factory = factory;
    }

    [Fact]
    public async Task LoginAndRefresh_ReturnTokenPairs()
    {
        var user = await CreateUserAsync();
        using var client = CreateClient();

        var login = await LoginAsync(client, user.UserName!);

        Assert.False(string.IsNullOrWhiteSpace(login.AccessToken));
        Assert.False(string.IsNullOrWhiteSpace(login.RefreshToken));
        Assert.True(login.AccessTokenExpiresAt > DateTimeOffset.UtcNow);

        var refreshResponse = await client.PostAsJsonAsync(
            "/auth/token/refresh",
            new { login.RefreshToken });
        var refreshed = await ReadTokenPairAsync(refreshResponse);

        Assert.NotEqual(login.AccessToken, refreshed.AccessToken);
        Assert.NotEqual(login.RefreshToken, refreshed.RefreshToken);
    }

    [Fact]
    public async Task Cookie_DoesNotAuthorizeBearerOnlyEndpoint()
    {
        var user = await CreateUserAsync();
        using var client = _factory.CreateClient(
            new WebApplicationFactoryClientOptions
            {
                BaseAddress = new Uri("https://localhost"),
                HandleCookies = true
            });

        var antiforgery = await client.GetFromJsonAsync<AntiforgeryResponse>(
            "/auth/antiforgery");
        using var request = new HttpRequestMessage(
            HttpMethod.Post,
            "/auth/login")
        {
            Content = JsonContent.Create(new
            {
                Identifier = user.UserName,
                Password,
                RememberMe = false
            })
        };
        request.Headers.Add("X-CSRF-TOKEN", antiforgery!.RequestToken);

        var cookieLogin = await client.SendAsync(request);
        Assert.Equal(HttpStatusCode.NoContent, cookieLogin.StatusCode);

        var response = await client.PostAsync(
            "/auth/token/logout-all",
            content: null);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Logout_RejectsRefreshTokenOwnedByAnotherUser()
    {
        var firstUser = await CreateUserAsync();
        var secondUser = await CreateUserAsync();
        using var client = CreateClient();
        var firstLogin = await LoginAsync(client, firstUser.UserName!);
        var secondLogin = await LoginAsync(client, secondUser.UserName!);
        SetBearer(client, firstLogin.AccessToken);

        var logout = await client.PostAsJsonAsync(
            "/auth/token/logout",
            new { secondLogin.RefreshToken });

        Assert.Equal(HttpStatusCode.Forbidden, logout.StatusCode);
        Assert.False(logout.Headers.Contains("Set-Cookie"));

        client.DefaultRequestHeaders.Authorization = null;
        var refresh = await client.PostAsJsonAsync(
            "/auth/token/refresh",
            new { secondLogin.RefreshToken });
        Assert.Equal(HttpStatusCode.OK, refresh.StatusCode);
    }

    [Fact]
    public async Task Logout_RevokesOnlyThatSession()
    {
        var user = await CreateUserAsync();
        using var client = CreateClient();
        var first = await LoginAsync(client, user.UserName!);
        var second = await LoginAsync(client, user.UserName!);
        SetBearer(client, first.AccessToken);

        var logout = await client.PostAsJsonAsync(
            "/auth/token/logout",
            new { first.RefreshToken });
        Assert.Equal(HttpStatusCode.NoContent, logout.StatusCode);

        client.DefaultRequestHeaders.Authorization = null;
        var revokedRefresh = await client.PostAsJsonAsync(
            "/auth/token/refresh",
            new { first.RefreshToken });
        var activeRefresh = await client.PostAsJsonAsync(
            "/auth/token/refresh",
            new { second.RefreshToken });

        Assert.Equal(HttpStatusCode.Unauthorized, revokedRefresh.StatusCode);
        Assert.Equal(HttpStatusCode.OK, activeRefresh.StatusCode);
    }

    [Fact]
    public async Task LogoutAll_RevokesEverySessionForCurrentUser()
    {
        var user = await CreateUserAsync();
        using var client = CreateClient();
        var first = await LoginAsync(client, user.UserName!);
        var second = await LoginAsync(client, user.UserName!);
        SetBearer(client, first.AccessToken);

        var logout = await client.PostAsync(
            "/auth/token/logout-all",
            content: null);
        Assert.Equal(HttpStatusCode.NoContent, logout.StatusCode);

        client.DefaultRequestHeaders.Authorization = null;
        var firstRefresh = await client.PostAsJsonAsync(
            "/auth/token/refresh",
            new { first.RefreshToken });
        var secondRefresh = await client.PostAsJsonAsync(
            "/auth/token/refresh",
            new { second.RefreshToken });

        Assert.Equal(HttpStatusCode.Unauthorized, firstRefresh.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, secondRefresh.StatusCode);
    }

    [Fact]
    public async Task Refresh_WhenUserIsLockedOut_Returns403WithoutCookie()
    {
        var user = await CreateUserAsync();
        using var client = CreateClient();
        var login = await LoginAsync(client, user.UserName!);
        await UpdateUserAsync(user.Id, currentUser =>
        {
            currentUser.LockoutEnabled = true;
            currentUser.LockoutEnd = DateTimeOffset.UtcNow.AddHours(1);
        });

        var response = await client.PostAsJsonAsync(
            "/auth/token/refresh",
            new { login.RefreshToken });

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.False(response.Headers.Contains("Set-Cookie"));
    }

    [Fact]
    public async Task Refresh_WhenUserIsNotAllowed_Returns403WithoutCookie()
    {
        var user = await CreateUserAsync();
        using var client = CreateClient();
        var login = await LoginAsync(client, user.UserName!);
        await UpdateUserAsync(user.Id, currentUser =>
            currentUser.EmailConfirmed = false);

        var response = await client.PostAsJsonAsync(
            "/auth/token/refresh",
            new { login.RefreshToken });

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.False(response.Headers.Contains("Set-Cookie"));
    }

    [Fact]
    public async Task Login_WhenTwoFactorIsEnabled_ReturnsNoTokens()
    {
        var user = await CreateUserAsync(twoFactorEnabled: true);
        using var client = CreateClient();

        var response = await client.PostAsJsonAsync(
            "/auth/token/login",
            new { Identifier = user.UserName, Password });
        var content = await response.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Contains("Two-factor authentication is required", content);
        Assert.DoesNotContain("accessToken", content);
        Assert.DoesNotContain("refreshToken", content);
    }

    private async Task<ApplicationUser> CreateUserAsync(
        bool twoFactorEnabled = false)
    {
        await using var scope = _factory.Services.CreateAsyncScope();
        var userManager = scope.ServiceProvider.GetRequiredService<
            UserManager<ApplicationUser>>();
        var userName = $"user-{Guid.NewGuid():N}";
        var user = new ApplicationUser
        {
            UserName = userName,
            Email = $"{userName}@example.com",
            EmailConfirmed = true
        };
        var create = await userManager.CreateAsync(user, Password);
        Assert.True(create.Succeeded, FormatErrors(create));

        if (twoFactorEnabled)
        {
            var enable = await userManager.SetTwoFactorEnabledAsync(user, true);
            Assert.True(enable.Succeeded, FormatErrors(enable));
        }

        return user;
    }

    private async Task UpdateUserAsync(
        Guid userId,
        Action<ApplicationUser> update)
    {
        await using var scope = _factory.Services.CreateAsyncScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<
            ApplicationDbContext>();
        var user = await dbContext.Users.SingleAsync(
            currentUser => currentUser.Id == userId);
        update(user);
        await dbContext.SaveChangesAsync();
    }

    private static async Task<TokenPairResponse> LoginAsync(
        HttpClient client,
        string identifier)
    {
        var response = await client.PostAsJsonAsync(
            "/auth/token/login",
            new { Identifier = identifier, Password });

        return await ReadTokenPairAsync(response);
    }

    private HttpClient CreateClient()
    {
        return _factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost")
        });
    }

    private static async Task<TokenPairResponse> ReadTokenPairAsync(
        HttpResponseMessage response)
    {
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        return (await response.Content.ReadFromJsonAsync<TokenPairResponse>())!;
    }

    private static void SetBearer(HttpClient client, string accessToken)
    {
        client.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", accessToken);
    }

    private static string FormatErrors(IdentityResult result)
    {
        return string.Join("; ", result.Errors.Select(error => error.Description));
    }

    private sealed record TokenPairResponse(
        string AccessToken,
        DateTimeOffset AccessTokenExpiresAt,
        string RefreshToken);

    private sealed record AntiforgeryResponse(string RequestToken);
}
