using Behrouzan.Auth.Permissions;

namespace Behrouzan.Auth.Tests.Permissions;

public class PermissionDefinitionTests
{
    [Fact]
    public void Constructor_ShouldSetNameAndDisplayName()
    {
        var permission = new PermissionDefinition(
            "Products.Create",
            "Create products");

        Assert.Equal("Products.Create", permission.Name);
        Assert.Equal("Create products", permission.DisplayName);
    }

    [Theory]
    [InlineData("")]
    [InlineData(" ")]
    public void Constructor_ShouldThrow_WhenNameIsEmpty(
        string name)
    {
        Assert.Throws<ArgumentException>(
            () => new PermissionDefinition(name));
    }
}