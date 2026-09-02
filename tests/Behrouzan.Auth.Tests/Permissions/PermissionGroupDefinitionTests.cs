using Behrouzan.Auth.Permissions;

namespace Behrouzan.Auth.Tests.Permissions;

public class PermissionGroupDefinitionTests
{
    [Fact]
    public void Constructor_ShouldSetNameAndDisplayName()
    {
        var group = new PermissionGroupDefinition(
            "Products",
            "Products", null);

        Assert.Equal("Products", group.Name);
        Assert.Equal("Products", group.DisplayName);
        Assert.Empty(group.Permissions);
    }

    [Fact]
    public void AddPermission_ShouldAddPermissionToGroup()
    {
        var group =
            new PermissionGroupDefinition("Products", null, null);

        var permission =
            group.AddPermission(
                "Products.Create",
                "Create products");

        Assert.Single(group.Permissions);
        Assert.Same(
            permission,
            group.Permissions[0]);

        Assert.Equal(
            "Products.Create",
            permission.Name);
    }

    [Theory]
    [InlineData("")]
    [InlineData(" ")]
    public void Constructor_ShouldThrow_WhenNameIsEmpty(
        string name)
    {
        Assert.Throws<ArgumentException>(
            () => new PermissionGroupDefinition(name, null, null));
    }

    [Fact]
    public void AddPermission_ShouldThrow_WhenPermissionAlreadyExists()
    {
        var group =
            new PermissionGroupDefinition("Products", null, null);

        group.AddPermission("Products.Create");

        Assert.Throws<InvalidOperationException>(
            () => group.AddPermission("Products.Create"));
    }
}