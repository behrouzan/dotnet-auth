using Microsoft.AspNetCore.Identity;
using Sample.Api.Identity;

namespace Sample.Api.Data;

internal static class DevelopmentUserSeeder
{
    public static async Task SeedAsync(
        UserManager<ApplicationUser> userManager)
    {
        const string userName = "behzad";

        if (await userManager.FindByNameAsync(userName) is not null)
        {
            return;
        }

        var user = new ApplicationUser
        {
            UserName = userName,
            Email = "behzad@example.com",
            PhoneNumber = "+15551234567"
        };

        var result = await userManager.CreateAsync(user, "Test123!");

        if (!result.Succeeded)
        {
            var errors = string.Join(
                "; ",
                result.Errors.Select(error => error.Description));

            throw new InvalidOperationException(
                $"Could not create the development sample user: {errors}");
        }
    }
}
