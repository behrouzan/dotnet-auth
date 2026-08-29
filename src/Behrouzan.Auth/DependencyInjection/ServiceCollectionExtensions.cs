using Behrouzan.Auth.Permissions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Behrouzan.Auth.DependencyInjection;

/// <summary>
/// Provides dependency injection extensions for configuring Behrouzan authentication services.
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Adds the core Behrouzan authentication services to the service collection.
    /// </summary>
    /// <param name="services">
    /// The service collection to add the services to.
    /// </param>
    /// <returns>
    /// The same service collection so that additional calls can be chained.
    /// </returns>
    public static IServiceCollection AddBehrouzanAuth(
        this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.TryAddSingleton<PermissionDefinitionManager>();

        services.TryAddSingleton<PermissionDefinitionCatalog>(
            serviceProvider =>
            {
                var manager =
                    serviceProvider.GetRequiredService<
                        PermissionDefinitionManager>();

                return manager.Build();
            });

        return services;
    }

    /// <summary>
    /// Adds a permission definition provider to the service collection.
    /// </summary>
    /// <typeparam name="TProvider">
    /// The permission definition provider type to register.
    /// </typeparam>
    /// <param name="services">
    /// The service collection to add the provider to.
    /// </param>
    /// <returns>
    /// The same service collection so that additional calls can be chained.
    /// </returns>
    public static IServiceCollection AddPermissionDefinition<
        TProvider>(
        this IServiceCollection services)
        where TProvider : PermissionDefinitionProvider
    {
        ArgumentNullException.ThrowIfNull(services);

        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<
                PermissionDefinitionProvider,
                TProvider>());

        return services;
    }
}