namespace AuthServer.Models;

public sealed class AuthServerOptions
{
    public string Issuer { get; set; } = "http://localhost:5080";

    public int AccessTokenLifetimeSeconds { get; set; } = 3600;

    public int IdTokenLifetimeSeconds { get; set; } = 3600;

    public int RefreshTokenLifetimeSeconds { get; set; } = 86400;

    // JWKS 応答の Cache-Control max-age (秒)。鍵ローテーションの猶予期間より短くすること
    public int JwksCacheMaxAgeSeconds { get; set; } = 3600;

    // 署名鍵の自動ローテーション間隔 (日)。0 で自動ローテーション無効 (管理画面からの手動のみ)
    public int SigningKeyRotationDays { get; set; }

    // ローテーション後に旧鍵を JWKS に公開し続ける猶予期間 (日)
    public int SigningKeyGraceDays { get; set; } = 7;

    // 期限切れデータのクリーンアップと鍵の自動ローテーションを実行する間隔 (分)
    public int MaintenanceIntervalMinutes { get; set; } = 60;
}
