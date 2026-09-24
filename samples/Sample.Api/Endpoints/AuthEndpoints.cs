using Behrouzan.Auth.Authentication;
using Behrouzan.Auth.AspNetCore.Authentication;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Sample.Api.Identity;

namespace Sample.Api.Endpoints;

internal static class AuthEndpoints
{
    public static IEndpointRouteBuilder MapAuthEndpoints(
        this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapPost(
            "/auth/login",
            LoginAsync)
            .AllowAnonymous();

        endpoints.MapGet(
            "/auth/me",
            GetCurrentUserAsync)
            .RequireAuthorization(policy => policy
                .AddAuthenticationSchemes(IdentityConstants.ApplicationScheme)
                .RequireAuthenticatedUser());

        endpoints.MapGet(
            "/auth/antiforgery",
            GetAntiforgeryToken)
            .AllowAnonymous();

        endpoints.MapPost(
            "/auth/logout",
            LogoutAsync)
            .RequireAuthorization(policy => policy
                .AddAuthenticationSchemes(IdentityConstants.ApplicationScheme)
                .RequireAuthenticatedUser());

        endpoints.MapPost(
            "/auth/token/login",
            TokenLoginAsync)
            .AllowAnonymous();

        endpoints.MapPost(
            "/auth/token/refresh",
            TokenRefreshAsync)
            .AllowAnonymous();

        endpoints.MapPost(
            "/auth/token/logout",
            TokenLogoutAsync)
            .RequireAuthorization(policy => policy
                .AddAuthenticationSchemes(JwtBearerDefaults.AuthenticationScheme)
                .RequireAuthenticatedUser());

        endpoints.MapPost(
            "/auth/token/logout-all",
            TokenLogoutAllAsync)
            .RequireAuthorization(policy => policy
                .AddAuthenticationSchemes(JwtBearerDefaults.AuthenticationScheme)
                .RequireAuthenticatedUser());

        return endpoints;
    }

    private static async Task<IResult> LoginAsync(
        LoginRequest request,
        HttpContext httpContext,
        IAntiforgery antiforgery,
        PasswordSignInManager<ApplicationUser> signInManager,
        CancellationToken cancellationToken)
    {
        try
        {
            await antiforgery.ValidateRequestAsync(httpContext);
        }
        catch (AntiforgeryValidationException)
        {
            return Results.BadRequest();
        }

        if (string.IsNullOrWhiteSpace(request.Identifier) ||
            string.IsNullOrWhiteSpace(request.Password))
        {
            return Results.Unauthorized();
        }

        var result = await signInManager.SignInAsync(
            request.Identifier,
            request.Password,
            request.RememberMe,
            cancellationToken);

        if (result.IsSuccess)
        {
            return Results.NoContent();
        }

        return result.ErrorCode switch
        {
            PasswordSignInErrorCode.RequiresTwoFactor => Results.Problem(
                title: "Two-factor authentication is required.",
                detail: "This sample does not implement a two-factor flow.",
                statusCode: StatusCodes.Status501NotImplemented),
            PasswordSignInErrorCode.InvalidCredentials => Results.Unauthorized(),
            PasswordSignInErrorCode.LockedOut => Results.Unauthorized(),
            PasswordSignInErrorCode.NotAllowed => Results.Unauthorized(),
            _ => Results.Unauthorized()
        };
    }

    private static async Task<IResult> GetCurrentUserAsync(
        HttpContext httpContext,
        UserManager<ApplicationUser> userManager)
    {
        var user = await userManager.GetUserAsync(httpContext.User);

        return user is null
            ? Results.Unauthorized()
            : Results.Ok(
                new CurrentUserResponse(
                    user.Id,
                    user.UserName,
                    user.Email,
                    user.PhoneNumber));
    }

    private static IResult GetAntiforgeryToken(
        HttpContext httpContext,
        IAntiforgery antiforgery)
    {
        var tokens = antiforgery.GetAndStoreTokens(httpContext);

        httpContext.Response.Headers.CacheControl = "no-store";

        return Results.Ok(
            new AntiforgeryTokenResponse(
                tokens.RequestToken ??
                throw new InvalidOperationException(
                    "An antiforgery request token was not generated.")));
    }

    private static async Task<IResult> LogoutAsync(
        HttpContext httpContext,
        IAntiforgery antiforgery)
    {
        try
        {
            await antiforgery.ValidateRequestAsync(httpContext);
        }
        catch (AntiforgeryValidationException)
        {
            return Results.BadRequest();
        }

        await httpContext.SignOutAsync(IdentityConstants.ApplicationScheme);

        return Results.NoContent();
    }

    private static async Task<IResult> TokenLoginAsync(
        TokenLoginRequest request,
        TokenLoginManager<ApplicationUser, Guid> loginManager,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(request.Identifier) ||
            string.IsNullOrWhiteSpace(request.Password))
        {
            return Results.Unauthorized();
        }

        var result = await loginManager.LoginAsync(
            request.Identifier,
            request.Password,
            cancellationToken);

        if (result.IsSuccess)
        {
            return Results.Ok(new TokenPairResponse(
                result.AccessToken!.Token,
                result.AccessToken.ExpiresAt,
                result.RefreshToken!));
        }

        return result.ErrorCode switch
        {
            TokenLoginErrorCode.RequiresTwoFactor => Results.Problem(
                title: "Two-factor authentication is required.",
                detail: "This sample does not implement token-based two-factor completion.",
                statusCode: StatusCodes.Status403Forbidden),
            TokenLoginErrorCode.RefreshTokenCreationFailed => Results.Problem(
                title: "Token creation failed.",
                statusCode: StatusCodes.Status503ServiceUnavailable),
            _ => Results.Unauthorized()
        };
    }

    private static async Task<IResult> TokenRefreshAsync(
        RefreshTokenRequest request,
        TokenRefreshManager<ApplicationUser, Guid> refreshManager,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(request.RefreshToken))
        {
            return Results.Unauthorized();
        }

        var result = await refreshManager.RefreshAsync(
            request.RefreshToken,
            cancellationToken);

        if (result.IsSuccess)
        {
            return Results.Ok(new TokenPairResponse(
                result.AccessToken!.Token,
                result.AccessToken.ExpiresAt,
                result.RefreshToken!));
        }

        return result.ErrorCode switch
        {
            TokenRefreshErrorCode.RequiresTwoFactor => Results.Problem(
                title: "Two-factor authentication is required.",
                detail: "Sign in again to satisfy current authentication requirements.",
                statusCode: StatusCodes.Status403Forbidden),
            TokenRefreshErrorCode.LockedOut or
            TokenRefreshErrorCode.NotAllowed => Results.StatusCode(
                StatusCodes.Status403Forbidden),
            TokenRefreshErrorCode.ConcurrencyConflict => Results.Conflict(),
            _ => Results.Unauthorized()
        };
    }

    private static async Task<IResult> TokenLogoutAsync(
        RefreshTokenRequest request,
        HttpContext httpContext,
        IRefreshTokenManager<Guid> refreshTokenManager,
        IRefreshTokenUserResolver<ApplicationUser, Guid> userResolver,
        CancellationToken cancellationToken)
    {
        var user = await ResolveBearerUserAsync(
            httpContext,
            userResolver,
            cancellationToken);

        if (user is null)
        {
            return Results.Unauthorized();
        }

        var validation = await refreshTokenManager.ValidateAsync(
            request.RefreshToken,
            cancellationToken);

        if (!validation.IsSuccess)
        {
            return Results.Unauthorized();
        }

        if (validation.UserId != user.Id)
        {
            return Results.Forbid(
                authenticationSchemes:
                [JwtBearerDefaults.AuthenticationScheme]);
        }

        await refreshTokenManager.RevokeAsync(
            request.RefreshToken,
            cancellationToken);

        return Results.NoContent();
    }

    private static async Task<IResult> TokenLogoutAllAsync(
        HttpContext httpContext,
        IRefreshTokenManager<Guid> refreshTokenManager,
        IRefreshTokenUserResolver<ApplicationUser, Guid> userResolver,
        CancellationToken cancellationToken)
    {
        var user = await ResolveBearerUserAsync(
            httpContext,
            userResolver,
            cancellationToken);

        if (user is null)
        {
            return Results.Unauthorized();
        }

        await refreshTokenManager.RevokeAllAsync(user.Id, cancellationToken);

        return Results.NoContent();
    }

    private static Task<ApplicationUser?> ResolveBearerUserAsync(
        HttpContext httpContext,
        IRefreshTokenUserResolver<ApplicationUser, Guid> userResolver,
        CancellationToken cancellationToken)
    {
        var subject = httpContext.User.FindFirstValue(
            JwtRegisteredClaimNames.Sub);

        return Guid.TryParse(subject, out var userId)
            ? userResolver.ResolveAsync(userId, cancellationToken)
            : Task.FromResult<ApplicationUser?>(null);
    }

    private sealed record LoginRequest(
        string Identifier,
        string Password,
        bool RememberMe);

    private sealed record TokenLoginRequest(
        string Identifier,
        string Password);

    private sealed record RefreshTokenRequest(string RefreshToken);

    private sealed record TokenPairResponse(
        string AccessToken,
        DateTimeOffset AccessTokenExpiresAt,
        string RefreshToken);

    private sealed record CurrentUserResponse(
        Guid Id,
        string? UserName,
        string? Email,
        string? PhoneNumber);

    private sealed record AntiforgeryTokenResponse(string RequestToken);
}
