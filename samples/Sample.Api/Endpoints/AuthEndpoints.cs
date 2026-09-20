using Behrouzan.Auth.AspNetCore.Authentication;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
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
            .RequireAuthorization();

        endpoints.MapGet(
            "/auth/antiforgery",
            GetAntiforgeryToken)
            .AllowAnonymous();

        endpoints.MapPost(
            "/auth/logout",
            LogoutAsync)
            .RequireAuthorization();

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

    private sealed record LoginRequest(
        string Identifier,
        string Password,
        bool RememberMe);

    private sealed record CurrentUserResponse(
        Guid Id,
        string? UserName,
        string? Email,
        string? PhoneNumber);

    private sealed record AntiforgeryTokenResponse(string RequestToken);
}
