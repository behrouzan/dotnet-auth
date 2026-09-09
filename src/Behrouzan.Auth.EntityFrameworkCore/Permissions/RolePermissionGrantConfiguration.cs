using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using Microsoft.AspNetCore.Identity;

namespace Behrouzan.Auth.EntityFrameworkCore.Permissions;

internal sealed class RolePermissionGrantConfiguration<TRole, TKey>
    : IEntityTypeConfiguration<RolePermissionGrant<TKey>>
    where TRole : IdentityRole<TKey>
    where TKey : IEquatable<TKey>
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

        builder.HasOne<TRole>()
            .WithMany()
            .HasForeignKey(x => x.RoleId)
            .OnDelete(DeleteBehavior.Cascade);
    }
}