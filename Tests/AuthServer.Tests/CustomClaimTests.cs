namespace AuthServer.Tests;

using System.Net;
using System.Text.Json;

using AuthServer.Models;
using AuthServer.Services;
using AuthServer.Tests.Infrastructure;

using Microsoft.Extensions.DependencyInjection;

// カスタムクレーム: 定義の検証、値の型変換、出力先 (AT / ID Token / UserInfo) と Discovery への反映
public sealed class CustomClaimTests : IClassFixture<AuthServerFactory>
{
    private readonly AuthServerFactory factory;

    public CustomClaimTests(AuthServerFactory factory)
    {
        this.factory = factory;
    }

    [Theory]
    [InlineData("email")]
    [InlineData("sub")]
    [InlineData("AUD")]
    [InlineData("1abc")]
    [InlineData("has space")]
    [InlineData("")]
    public void ReservedOrMalformedClaimTypesAreRejected(string claimType)
    {
        Assert.NotNull(CustomClaimService.ValidateClaimType(claimType));
    }

    [Theory]
    [InlineData("department")]
    [InlineData("employee_id")]
    [InlineData("urn:example:role")]
    public void WellFormedClaimTypesAreAccepted(string claimType)
    {
        Assert.Null(CustomClaimService.ValidateClaimType(claimType));
    }

    [Fact]
    public void ValuesAreConvertedAccordingToTheDeclaredType()
    {
        Assert.Equal(42L, CustomClaimService.ConvertValue(CustomClaimService.TypeNumber, "42"));
        Assert.Equal(1.5, CustomClaimService.ConvertValue(CustomClaimService.TypeNumber, "1.5"));
        Assert.Equal(true, CustomClaimService.ConvertValue(CustomClaimService.TypeBoolean, "true"));
        Assert.Equal("plain", CustomClaimService.ConvertValue(CustomClaimService.TypeString, "plain"));

        var json = Assert.IsType<JsonElement>(CustomClaimService.ConvertValue(CustomClaimService.TypeJson, """{"a":1}"""));
        Assert.Equal(JsonValueKind.Object, json.ValueKind);

        Assert.NotNull(CustomClaimService.ValidateValue(CustomClaimService.TypeNumber, "abc"));
        Assert.NotNull(CustomClaimService.ValidateValue(CustomClaimService.TypeBoolean, "yes"));
        Assert.NotNull(CustomClaimService.ValidateValue(CustomClaimService.TypeJson, "{"));
        Assert.Null(CustomClaimService.ValidateValue(CustomClaimService.TypeJson, "[1,2]"));
    }

    [Fact]
    public async Task DefinedClaimIsEmittedToTheConfiguredTargetsUntilDeleted()
    {
        var service = factory.Services.GetRequiredService<CustomClaimService>();
        await service.SaveDefinitionAsync(new ClaimDefinition
        {
            ClaimType = "employee_id",
            Description = "test",
            ValueType = CustomClaimService.TypeNumber,
            RequiredScope = null,
            InAccessToken = true,
            InIdToken = true,
            InUserInfo = true
        });
        await service.SetUserClaimAsync("user-001", "employee_id", "1024");

        using var client = factory.CreateClient();
        var tokens = await Oauth.AuthorizeAndExchangeAsync(client, "openid");

        var access = Oauth.JwtPayload(tokens.GetString("access_token")!).GetProperty("employee_id");
        Assert.Equal(JsonValueKind.Number, access.ValueKind);
        Assert.Equal(1024, access.GetInt64());
        Assert.Equal(1024, Oauth.JwtPayload(tokens.GetString("id_token")!).GetProperty("employee_id").GetInt64());

        var userInfo = await Oauth.UserInfoAsync(client, tokens.GetString("access_token")!);
        Assert.Equal(1024, userInfo.Property("employee_id").GetInt64());

        var discovery = await Oauth.GetAsync(client, Oauth.DiscoveryPath);
        Assert.Contains("employee_id", discovery.GetStringArray("claims_supported"));

        // 定義を削除するとユーザーの値も消え、トークンに出なくなる
        await service.DeleteDefinitionAsync("employee_id");
        Assert.DoesNotContain(await service.QueryUserClaimListAsync("user-001"), c => c.ClaimType == "employee_id");

        var after = await Oauth.AuthorizeAndExchangeAsync(client, "openid");
        Assert.False(Oauth.JwtPayload(after.GetString("access_token")!).TryGetProperty("employee_id", out _));
        Assert.DoesNotContain("employee_id", (await Oauth.GetAsync(client, Oauth.DiscoveryPath)).GetStringArray("claims_supported"));
    }

    [Fact]
    public async Task RequiredScopeAddsItselfToTheAdvertisedScopes()
    {
        var service = factory.Services.GetRequiredService<CustomClaimService>();
        await service.SaveDefinitionAsync(new ClaimDefinition
        {
            ClaimType = "cost_center",
            ValueType = CustomClaimService.TypeString,
            RequiredScope = "hr.read",
            InIdToken = true
        });

        using var client = factory.CreateClient();
        var discovery = await Oauth.GetAsync(client, Oauth.DiscoveryPath);
        Assert.Equal(HttpStatusCode.OK, discovery.Status);
        Assert.Contains("hr.read", discovery.GetStringArray("scopes_supported"));
        Assert.Contains("cost_center", discovery.GetStringArray("claims_supported"));

        await service.DeleteDefinitionAsync("cost_center");
    }

    [Fact]
    public async Task BlankValueRemovesTheUserClaim()
    {
        var service = factory.Services.GetRequiredService<CustomClaimService>();
        await service.SetUserClaimAsync("user-001", "department", "Sales");
        Assert.Equal("Sales", (await service.QueryUserClaimListAsync("user-001")).Single(c => c.ClaimType == "department").Value);

        await service.SetUserClaimAsync("user-001", "department", "   ");
        Assert.DoesNotContain(await service.QueryUserClaimListAsync("user-001"), c => c.ClaimType == "department");

        // 他のテストのために seed の値を戻す
        await service.SetUserClaimAsync("user-001", "department", "Engineering");
    }
}
