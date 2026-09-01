using Behrouzan.Auth.EntityFrameworkCore.Permissions;
using Behrouzan.Auth.Permissions;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Behrouzan.Auth.EntityFrameworkCore.DependencyInjection;

/// <summary>
/// Provides dependency injection extensions for configuring
/// Entity Framework Core persistence for Behrouzan authentication.
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Adds Entity Framework Core persistence services required by
    /// Behrouzan authentication.
    /// </summary>
    /// <typeparam name="TContext">
    /// The Identity Entity Framework Core database context type.
    /// </typeparam>
    /// <typeparam name="TUser">
    /// The Identity user type.
    /// </typeparam>
    /// <typeparam name="TRole">
    /// The Identity role type.
    /// </typeparam>
    /// <typeparam name="TKey">
    /// The type used to identify users and roles.
    /// </typeparam>
    /// <param name="services">
    /// The service collection to configure.
    /// </param>
    /// <returns>
    /// The same service collection so that additional configuration
    /// can be chained.
    /// </returns>
    public static IServiceCollection
        AddBehrouzanAuthEntityFrameworkCore<
            TContext,
            TUser,
            TRole,
            TKey>(
            this IServiceCollection services)
        where TContext : IdentityDbContext<
            TUser,
            TRole,
            TKey>
        where TUser : IdentityUser<TKey>
        where TRole : IdentityRole<TKey>
        where TKey : IEquatable<TKey>
    {
        ArgumentNullException.ThrowIfNull(services);

        services.TryAddScoped<
            IPermissionGrantStore<TKey>,
            EfPermissionGrantStore<
                TContext,
                TUser,
                TRole,
                TKey>>();

        return services;
    }
}