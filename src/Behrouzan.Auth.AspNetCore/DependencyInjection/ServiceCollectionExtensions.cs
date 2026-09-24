using Behrouzan.Auth.AspNetCore.Authorization;
using Behrouzan.Auth.AspNetCore.Users;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Behrouzan.Auth.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;

namespace Behrouzan.Auth.AspNetCore.DependencyInjection;

/// <summary>
/// Provides dependency injection extensions for configuring
/// Behrouzan authentication with ASP.NET Core.
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Adds token-login orchestration for an application-supplied token user identity resolver.
    /// </summary>
    /// <typeparam name="TUser">The application user type.</typeparam>
    /// <typeparam name="TKey">The type of the persisted user identifier.</typeparam>
    /// <param name="services">The service collection to configure.</param>
    /// <returns>The same service collection so that additional configuration can be chained.</returns>
    /// <remarks>
    /// Applications using a custom Identity user model must register an
    /// <see cref="ITokenUserIdentityResolver{TUser, TKey}"/> separately.
    /// </remarks>
    public static IServiceCollection AddBehrouzanTokenLogin<TUser, TKey>(
        this IServiceCollection services)
        where TUser : class
        where TKey : notnull
    {
        ArgumentNullException.ThrowIfNull(services);

        services.TryAddScoped<TokenLoginManager<TUser, TKey>>();

        return services;
    }

    /// <summary>
    /// Adds token-login orchestration and the standard resolver for an
    /// <see cref="IdentityUser{TKey}"/>-based user type.
    /// </summary>
    /// <typeparam name="TUser">The Identity user type.</typeparam>
    /// <typeparam name="TKey">The type of the Identity user identifier.</typeparam>
    /// <param name="services">The service collection to configure.</param>
    /// <returns>The same service collection so that additional configuration can be chained.</returns>
    public static IServiceCollection AddBehrouzanIdentityTokenLogin<TUser, TKey>(
        this IServiceCollection services)
        where TUser : IdentityUser<TKey>
        where TKey : notnull, IEquatable<TKey>
    {
        ArgumentNullException.ThrowIfNull(services);

        services.TryAddScoped<
            ITokenUserIdentityResolver<TUser, TKey>,
            DefaultTokenUserIdentityResolver<TUser, TKey>>();

        return services.AddBehrouzanTokenLogin<TUser, TKey>();
    }

    /// <summary>
    /// Adds access-token issuance services for explicitly supplied signing credentials.
    /// </summary>
    /// <param name="services">The service collection to configure.</param>
    /// <param name="configure">An optional delegate used to configure access-token issuance.</param>
    /// <returns>The same service collection so that additional configuration can be chained.</returns>
    public static IServiceCollection AddBehrouzanAccessTokens(
        this IServiceCollection services,
        Action<AccessTokenOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(services);

        services
            .AddOptions<AccessTokenOptions>()
            .Validate(
                options => !string.IsNullOrWhiteSpace(options.Issuer),
                "Access token issuer must be non-empty.")
            .Validate(
                options => !string.IsNullOrWhiteSpace(options.Audience),
                "Access token audience must be non-empty.")
            .Validate(
                options => options.Lifetime > TimeSpan.Zero,
                "Access token lifetime must be greater than zero.")
            .ValidateOnStart();

        if (configure is not null)
        {
            services.Configure(configure);
        }

        services.TryAddScoped<AccessTokenManager>();
        services.TryAddSingleton(TimeProvider.System);

        return services;
    }

    /// <summary>
    /// Adds ASP.NET Core authorization services required by
    /// Behrouzan authentication.
    /// </summary>
    /// <typeparam name="TKey">
    /// The type used to identify users.
    /// </typeparam>
    /// <param name="services">
    /// The service collection to configure.
    /// </param>
    /// <returns>
    /// The same service collection so that additional configuration
    /// can be chained.
    /// </returns>
    public static IServiceCollection AddBehrouzanAuthAspNetCore<TKey>(
        this IServiceCollection services)
        where TKey : notnull
    {
        ArgumentNullException.ThrowIfNull(services);

        services.TryAddScoped<
            IUserIdResolver<TKey>,
            DefaultUserIdResolver<TKey>>();

        services.TryAddEnumerable(
            ServiceDescriptor.Scoped<
                IAuthorizationHandler,
                PermissionAuthorizationHandler<TKey>>());

        services.Replace(
            ServiceDescriptor.Singleton<
                IAuthorizationPolicyProvider,
                PermissionAuthorizationPolicyProvider>());

        return services;
    }

    /// <summary>
    /// Adds password sign-in services for the specified ASP.NET Core
    /// Identity user type.
    /// </summary>
    /// <typeparam name="TUser">
    /// The application user type.
    /// </typeparam>
    /// <param name="services">
    /// The service collection to configure.
    /// </param>
    /// <param name="configure">
    /// An optional delegate used to configure password sign-in.
    /// </param>
    /// <returns>
    /// The same service collection so that additional configuration
    /// can be chained.
    /// </returns>
    public static IServiceCollection AddBehrouzanPasswordSignIn<TUser>(
        this IServiceCollection services,
        Action<PasswordSignInOptions>? configure = null)
        where TUser : class
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddOptions<PasswordSignInOptions>();

        if (configure is not null)
        {
            services.Configure(configure);
        }

        services.TryAddScoped<
            IUserSignInResolver<TUser>,
            DefaultUserSignInResolver<TUser>>();

        services.TryAddScoped<PasswordAuthenticationManager<TUser>>();

        services.TryAddScoped<PasswordSignInManager<TUser>>();

        return services;
    }
}
