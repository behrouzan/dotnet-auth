using System.ComponentModel;
using System.Globalization;
using System.Security.Claims;

namespace Behrouzan.Auth.AspNetCore.Users;

internal sealed class DefaultUserIdResolver<TKey>
    : IUserIdResolver<TKey>
    where TKey : notnull
{
    public bool TryResolve(
        ClaimsPrincipal principal,
        out TKey userId)
    {
        ArgumentNullException.ThrowIfNull(principal);

        var value =
            principal.FindFirstValue(
                ClaimTypes.NameIdentifier);

        if (string.IsNullOrWhiteSpace(value))
        {
            userId = default!;
            return false;
        }

        try
        {
            var converter =
                TypeDescriptor.GetConverter(
                    typeof(TKey));

            if (!converter.CanConvertFrom(
                    typeof(string)))
            {
                userId = default!;
                return false;
            }

            var converted =
                converter.ConvertFrom(
                    null,
                    CultureInfo.InvariantCulture,
                    value);

            if (converted is not TKey typedUserId)
            {
                userId = default!;
                return false;
            }

            userId = typedUserId;
            return true;
        }
        catch (Exception exception)
            when (exception is FormatException
                or NotSupportedException
                or ArgumentException)
        {
            userId = default!;
            return false;
        }
    }
}