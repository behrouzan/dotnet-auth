using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Behrouzan.Auth.EntityFrameworkCore.Permissions;

internal sealed class RolePermissionGrantConfiguration<TKey>
    : IEntityTypeConfiguration<RolePermissionGrant<TKey>>
    where TKey : notnull
{
    public void Configure(
        EntityTypeBuilder<RolePermissionGrant<TKey>> builder)
    {
        builder.ToTable("BehrouzanRolePermissionGrants");

        builder.HasKey(
            grant => new
            {
                grant.RoleId,
                grant.PermissionName
            });

        builder.Property(
                grant => grant.PermissionName)
            .HasMaxLength(256)
            .IsRequired();
    }
}