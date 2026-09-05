namespace AuthServer.Services;

using System.Data.Common;

using AuthServer.Models;

using Microsoft.Extensions.Options;

// 期限切れデータのクリーンアップと署名鍵の自動ローテーションを定期実行するバックグラウンドサービス。
public sealed class MaintenanceService(
    AuthorizationCodeService codeService,
    RefreshTokenService refreshTokenService,
    RevokedTokenService revokedTokenService,
    SigningKeyService signingKeyService,
    IOptions<AuthServerOptions> options,
    ILogger<MaintenanceService> logger) : BackgroundService
{
    private static readonly TimeSpan StartupDelay = TimeSpan.FromSeconds(10);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var interval = TimeSpan.FromMinutes(Math.Max(1, options.Value.MaintenanceIntervalMinutes));
        await Task.Delay(StartupDelay, stoppingToken);

        using var timer = new PeriodicTimer(interval);
        do
        {
            await RunOnceAsync();
        }
        while (await timer.WaitForNextTickAsync(stoppingToken));
    }

    private async Task RunOnceAsync()
    {
        try
        {
            var now = DateTime.UtcNow;
            var codes = await codeService.DeleteExpiredAsync(now);
            var refreshTokens = await refreshTokenService.DeleteExpiredAsync(now);
            var revokedTokens = await revokedTokenService.DeleteExpiredAsync(now);
            var retiredKeys = signingKeyService.RetireExpiredKeys(now);
            var rotated = RotateKeyIfDue(now);

            if (logger.IsEnabled(LogLevel.Information))
            {
                logger.LogInformation(
                    "Maintenance completed: expired codes={Codes}, expired refresh tokens={RefreshTokens}, expired revocations={Revocations}, retired keys={RetiredKeys}, key rotated={Rotated}",
                    codes, refreshTokens, revokedTokens, retiredKeys, rotated);
            }
        }
        catch (DbException ex)
        {
            logger.LogError(ex, "Maintenance failed (database error).");
        }
        catch (InvalidOperationException ex)
        {
            logger.LogError(ex, "Maintenance failed.");
        }
    }

    // 現用鍵が SigningKeyRotationDays より古ければローテーションする。0 以下なら自動ローテーションしない。
    private bool RotateKeyIfDue(DateTime now)
    {
        var rotationDays = options.Value.SigningKeyRotationDays;
        if (rotationDays <= 0)
        {
            return false;
        }

        var createdAt = signingKeyService.GetCurrentKeyCreatedAt();
        if ((createdAt is null) || (now - createdAt.Value < TimeSpan.FromDays(rotationDays)))
        {
            return false;
        }

        var kid = signingKeyService.RotateKey(TimeSpan.FromDays(options.Value.SigningKeyGraceDays));
        if (logger.IsEnabled(LogLevel.Information))
        {
            logger.LogInformation("Signing key rotated automatically. New kid: {Kid}", kid);
        }

        return true;
    }
}
