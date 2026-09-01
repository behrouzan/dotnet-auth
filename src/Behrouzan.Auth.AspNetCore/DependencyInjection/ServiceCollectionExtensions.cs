using Behrouzan.Auth.AspNetCore.Authorization;
using Behrouzan.Auth.AspNetCore.Users;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Behrouzan.Auth.AspNetCore.DependencyInjection;

/// <summary>
/// Provides dependency injection extensions for configuring
/// Behrouzan authentication with ASP.NET Core.
/// </summary>
public static class ServiceCollectionExtensions
{
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
}