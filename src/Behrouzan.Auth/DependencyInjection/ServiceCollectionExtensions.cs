using Behrouzan.Auth.Authentication;
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

        services.TryAddScoped(
            typeof(IPermissionChecker<>),
            typeof(PermissionChecker<>));

        services.TryAddSingleton<PermissionDefinitionCatalog>(
            serviceProvider =>
            {
                var manager =
                    serviceProvider.GetRequiredService<
                        PermissionDefinitionManager>();

                return manager.Build();
            });

        services.TryAddScoped(typeof(RolePermissionManager<>));
        
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

    /// <summary>
    /// Adds refresh token services and configuration to the service collection.
    /// </summary>
    /// <param name="services">
    /// The service collection to add the services to.
    /// </param>
    /// <param name="configure">
    /// An optional action used to configure refresh token options.
    /// </param>
    /// <returns>
    /// The same service collection so that additional calls can be chained.
    /// </returns>
    public static IServiceCollection AddRefreshTokens(
        this IServiceCollection services,
        Action<RefreshTokenOptions>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(services);

        //services.AddOptions<RefreshTokenOptions>();
        services
            .AddOptions<RefreshTokenOptions>()
            .Validate(
                options => options.Lifetime > TimeSpan.Zero,
                "Refresh token lifetime must be greater than zero.")
            .ValidateOnStart();

        if (configure is not null)
        {
            services.Configure(configure);
        }

        services.TryAddSingleton<RefreshTokenHasher>();
        services.TryAddSingleton<RefreshTokenGenerator>();

        services.TryAddScoped(
            typeof(IRefreshTokenManager<>),
            typeof(RefreshTokenManager<>));

        services.TryAddSingleton(TimeProvider.System);


        return services;
    }

}