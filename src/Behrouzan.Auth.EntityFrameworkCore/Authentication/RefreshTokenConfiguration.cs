using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Behrouzan.Auth.EntityFrameworkCore.Authentication;

internal sealed class RefreshTokenConfiguration<TUser, TKey>
    : IEntityTypeConfiguration<RefreshToken<TKey>>
    where TUser : IdentityUser<TKey>
    where TKey : IEquatable<TKey>
{
    public void Configure(
        EntityTypeBuilder<RefreshToken<TKey>> builder)
    {
        builder.ToTable("BehrouzanRefreshTokens");

        builder.HasKey(x => x.TokenId);

        builder.HasIndex(x => x.TokenHash)
            .IsUnique();
        
        builder.Property(x => x.TokenHash)
            .IsRequired()
            .HasMaxLength(32);

        builder.HasIndex(x => x.UserId);

        builder.HasOne<RefreshToken<TKey>>()
            .WithOne()
            .HasForeignKey<RefreshToken<TKey>>(x => x.ReplacedByTokenId)
            .OnDelete(DeleteBehavior.Restrict);

        builder.HasOne<TUser>()
            .WithMany()
            .HasForeignKey(x => x.UserId)
            .OnDelete(DeleteBehavior.Cascade);

    }
}