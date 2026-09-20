using Behrouzan.Auth.Authentication;

namespace Behrouzan.Auth.Tests.Authentication;

public sealed class UserIdentifierTypeTests
{
    [Fact]
    public void Constructor_ShouldCreateConsumerDefinedIdentifierType()
    {
        var identifierType = new UserIdentifierType("customer-number");

        Assert.Equal("customer-number", identifierType.Value);
        Assert.NotEqual(UserIdentifierType.PhoneNumber, identifierType);
    }

    [Fact]
    public void Constructor_ShouldRejectEmptyIdentifierType()
    {
        Assert.Throws<ArgumentException>(
            () => new UserIdentifierType(" "));
    }
}
