using Microsoft.Extensions.Configuration;
using PrivacyLink.Api;

public sealed class ChromeExtensionOriginTests
{
    private const string ValidOrigin = "chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    [Fact]
    public void ConfigurationMayLeaveExtensionCreationDisabled()
    {
        var configuration = ConfigurationWithExtensionOrigin(string.Empty);

        ProductionConfiguration.Validate(configuration, isProduction: false);

        Assert.Null(ChromeExtensionOrigin.Read(configuration));
    }

    [Fact]
    public void ConfigurationAcceptsOneExactChromeExtensionOrigin()
    {
        var configuration = ConfigurationWithExtensionOrigin(ValidOrigin);

        ProductionConfiguration.Validate(configuration, isProduction: false);

        Assert.Equal(ValidOrigin, ChromeExtensionOrigin.Read(configuration));
    }

    [Theory]
    [InlineData("chrome-extension://*")]
    [InlineData("chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")]
    [InlineData("chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/")]
    [InlineData("chrome-extension://AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")]
    [InlineData("https://example.com")]
    [InlineData(" chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")]
    public void ConfigurationRejectsNonExactOrWildcardOrigins(string origin)
    {
        var configuration = ConfigurationWithExtensionOrigin(origin);

        var error = Assert.Throws<InvalidOperationException>(() => ProductionConfiguration.Validate(configuration, isProduction: false));

        Assert.Contains("ChromeExtensionOrigin", error.Message, StringComparison.Ordinal);
    }

    private static IConfiguration ConfigurationWithExtensionOrigin(string origin) => new ConfigurationBuilder()
        .AddInMemoryCollection(new Dictionary<string, string?>
        {
            ["Security:CreateProofHmacKey"] = Convert.ToBase64String(new byte[32]),
            ["Security:CreateProofDifficultyBits"] = "17",
            ["Security:ChromeExtensionOrigin"] = origin
        })
        .Build();
}
