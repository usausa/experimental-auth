namespace AuthServer.Services;

using System.Data.Common;

using AuthServer.Models;

using Microsoft.Extensions.Options;

// 期限切れデータのクリーンアップと署名鍵の世代交代 (予約鍵の昇格・自動ローテーションの予約・猶予期間切れの退役) を定期実行する。
public sealed class MaintenanceService(
    AuthorizationCodeService codeService,
    DeviceCodeService deviceCodeService,
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
            var deviceCodes = await deviceCodeService.DeleteExpiredAsync(now);
            var refreshTokens = await refreshTokenService.DeleteExpiredAsync(now);
            var revokedTokens = await revokedTokenService.DeleteExpiredAsync(now);
            var promoted = signingKeyService.PromoteDueKeys(now);
            var retiredKeys = signingKeyService.RetireExpiredKeys(now);
            var scheduled = ScheduleRotationIfDue(now);

            if (logger.IsEnabled(LogLevel.Information))
            {
                logger.LogInformation(
                    "Maintenance completed: expired codes={Codes}, expired device codes={DeviceCodes}, expired refresh tokens={RefreshTokens}, expired revocations={Revocations}, key promoted={Promoted}, retired keys={RetiredKeys}, rotation scheduled={Scheduled}",
                    codes, deviceCodes, refreshTokens, revokedTokens, promoted, retiredKeys, scheduled);
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

    // 現用鍵が SigningKeyRotationDays より古ければ、次の鍵を予約する (事前公開)。0 以下なら自動ローテーションしない。
    private bool ScheduleRotationIfDue(DateTime now)
    {
        var rotationDays = options.Value.SigningKeyRotationDays;
        if ((rotationDays <= 0) || signingKeyService.HasPendingKey())
        {
            return false;
        }

        var createdAt = signingKeyService.GetCurrentKeyCreatedAt();
        if ((createdAt is null) || (now - createdAt.Value < TimeSpan.FromDays(rotationDays)))
        {
            return false;
        }

        var kid = signingKeyService.ScheduleRotation(options.Value.SigningKeyAlgorithm);
        if (logger.IsEnabled(LogLevel.Information))
        {
            logger.LogInformation("Signing key rotation scheduled automatically. Pending kid: {Kid}", kid);
        }

        return true;
    }
}
