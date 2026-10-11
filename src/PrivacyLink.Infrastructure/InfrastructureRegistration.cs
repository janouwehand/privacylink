using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using PrivacyLink.Services;

namespace PrivacyLink.Infrastructure;

public static class InfrastructureRegistration
{
    public static IServiceCollection AddPrivacyLinkInfrastructure(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddSingleton<StorageHealth>();
        services.AddSingleton<IStorageReadiness>(sp => sp.GetRequiredService<StorageHealth>());
        if (configuration.GetConnectionString("PrivacyLink") is not null)
        {
            services.AddSingleton<PostgresSecretRequestAuditWriter>();
            services.AddSingleton<ISecretRequestAuditWriter>(sp => sp.GetRequiredService<PostgresSecretRequestAuditWriter>());
            services.AddSingleton<ISecretRequestAuditReader>(sp => sp.GetRequiredService<PostgresSecretRequestAuditWriter>());
            services.AddSingleton<PostgresSecretRepository>();
            services.AddSingleton<ISecretRepository>(sp => sp.GetRequiredService<PostgresSecretRepository>());
            services.AddSingleton<IInfrastructureHealthCheck>(sp => sp.GetRequiredService<PostgresSecretRepository>());
            services.AddSingleton<IInfrastructureInitializer>(sp => sp.GetRequiredService<PostgresSecretRepository>());
            services.AddSingleton<FileBlobStorage>();
            services.AddSingleton<IBlobStorage>(sp => sp.GetRequiredService<FileBlobStorage>());
            services.AddSingleton<IInfrastructureHealthCheck>(sp => sp.GetRequiredService<FileBlobStorage>());
            services.AddSingleton<IInfrastructureInitializer>(sp => sp.GetRequiredService<FileBlobStorage>());
        }
        else
        {
            services.AddSingleton<InMemorySecretRequestAuditWriter>();
            services.AddSingleton<ISecretRequestAuditWriter>(sp => sp.GetRequiredService<InMemorySecretRequestAuditWriter>());
            services.AddSingleton<ISecretRequestAuditReader>(sp => sp.GetRequiredService<InMemorySecretRequestAuditWriter>());
            services.AddSingleton<InMemorySecretRepository>();
            services.AddSingleton<ISecretRepository>(sp => sp.GetRequiredService<InMemorySecretRepository>());
            services.AddSingleton<IInfrastructureHealthCheck>(sp => sp.GetRequiredService<InMemorySecretRepository>());
            services.AddSingleton<IInfrastructureInitializer>(sp => sp.GetRequiredService<InMemorySecretRepository>());
            services.AddSingleton<InMemoryBlobStorage>();
            services.AddSingleton<IBlobStorage>(sp => sp.GetRequiredService<InMemoryBlobStorage>());
            services.AddSingleton<IInfrastructureHealthCheck>(sp => sp.GetRequiredService<InMemoryBlobStorage>());
        }

        services.AddHostedService<StorageInitializer>();
        services.AddHostedService<ExpiredSecretCleanup>();
        return services;
    }
}
