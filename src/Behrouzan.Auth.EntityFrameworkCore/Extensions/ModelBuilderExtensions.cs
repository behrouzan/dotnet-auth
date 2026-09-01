using Behrouzan.Auth.EntityFrameworkCore.Permissions;
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
    public static ModelBuilder ConfigureBehrouzanAuth<TKey>(
        this ModelBuilder modelBuilder)
        where TKey : notnull
    {
        ArgumentNullException.ThrowIfNull(modelBuilder);

        modelBuilder.ApplyConfiguration(
            new RolePermissionGrantConfiguration<TKey>());

        return modelBuilder;
    }
}