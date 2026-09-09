namespace AuthServer.Tests;

using AuthServer.Services;
using AuthServer.Tests.Infrastructure;

using Microsoft.Extensions.DependencyInjection;

// エンドポイントを介さないサービス単体の振る舞い (リプレイ記録の一回性と期限、監査ログの検索と保持期間)
public sealed class ServiceTests : IClassFixture<AuthServerFactory>
{
    private readonly AuthServerFactory factory;

    public ServiceTests(AuthServerFactory factory)
    {
        this.factory = factory;
    }

    [Fact]
    public async Task ReplayGuardRegistersAValueOnlyOnceUntilItExpires()
    {
        var guard = factory.Services.GetRequiredService<ReplayGuardService>();
        var value = "value-" + Guid.NewGuid().ToString("N");

        Assert.True(await guard.TryRegisterAsync("unit-test", value, "client", DateTime.UtcNow.AddSeconds(-1)));
        Assert.False(await guard.TryRegisterAsync("unit-test", value, "client", DateTime.UtcNow.AddMinutes(5)));

        // 同じ値でも kind が違えば別物
        Assert.True(await guard.TryRegisterAsync("unit-test-other-kind", value, "client", DateTime.UtcNow.AddMinutes(5)));

        Assert.True(await guard.DeleteExpiredAsync(DateTime.UtcNow) >= 1);
        Assert.True(await guard.TryRegisterAsync("unit-test", value, "client", DateTime.UtcNow.AddMinutes(5)));
    }

    [Fact]
    public async Task AuditLogRecordsFiltersAndPurgesEntries()
    {
        var auditLog = factory.Services.GetRequiredService<AuditLogService>();
        var marker = "marker-" + Guid.NewGuid().ToString("N");
        await auditLog.RecordAsync(new AuditEntry("unit_test_event", AuditOutcome.Info, "unit-client", "user-x", "subject-x", "127.0.0.1", "detail " + marker));
        await auditLog.RecordAsync(new AuditEntry("unit_test_event", AuditOutcome.Failure, "other-client", null, null, null, "unrelated"));

        var byClient = await auditLog.QueryAsync(new AuditLogFilter("unit_test_event", null, "unit-client", null), 10);
        var entry = Assert.Single(byClient);
        Assert.Equal("user-x", entry.UserId);
        Assert.Equal("subject-x", entry.Subject);
        Assert.Equal("127.0.0.1", entry.IpAddress);
        Assert.Contains(marker, entry.Detail, StringComparison.Ordinal);

        var bySearch = await auditLog.QueryAsync(new AuditLogFilter(null, null, null, marker), 10);
        Assert.Single(bySearch);

        var byOutcome = await auditLog.QueryAsync(new AuditLogFilter("unit_test_event", AuditOutcome.Failure, null, null), 10);
        Assert.Single(byOutcome);

        Assert.Contains("unit_test_event", await auditLog.QueryEventTypesAsync());

        Assert.True(await auditLog.DeleteOlderThanAsync(DateTime.UtcNow.AddMinutes(1)) >= 2);
        Assert.Empty(await auditLog.QueryAsync(new AuditLogFilter("unit_test_event", null, null, null), 10));
    }
}
