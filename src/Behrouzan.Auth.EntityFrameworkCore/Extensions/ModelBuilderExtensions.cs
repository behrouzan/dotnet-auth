using Behrouzan.Auth.EntityFrameworkCore.Authentication;
using Behrouzan.Auth.EntityFrameworkCore.Permissions;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace Behrouzan.Auth.EntityFrameworkCore.Extensions;

/// <summary>
/// Provides model-building extensions for configuring
/// Behrouzan authentication persistence.
/// </summary>
public static class ModelBuilderExtensions
{
    /// <summary>
    /// Configures the Entity Framework Core model required by
    /// Behrouzan authentication services.
    /// </summary>
    /// <typeparam name="TUser">
    /// The Identity user type.
    /// </typeparam>
    /// <typeparam name="TRole">
    /// The Identity role type.
    /// </typeparam>
    /// <typeparam name="TKey">
    /// The type used to identify Identity users and roles.
    /// </typeparam>
    /// <param name="modelBuilder">
    /// The model builder to configure.
    /// </param>
    /// <returns>
    /// The same model builder instance so that additional configuration
    /// can be chained.
    /// </returns>
    public static ModelBuilder ConfigureBehrouzanAuth<TUser, TRole, TKey>(
        this ModelBuilder modelBuilder)
        where TUser : IdentityUser<TKey>
        where TRole : IdentityRole<TKey>
        where TKey : IEquatable<TKey>
    {
        ArgumentNullException.ThrowIfNull(modelBuilder);

        modelBuilder.ApplyConfiguration(
            new RolePermissionGrantConfiguration<TRole, TKey>());

        modelBuilder.ApplyConfiguration(
            new RefreshTokenConfiguration<TUser, TKey>());

        return modelBuilder;
    }
}