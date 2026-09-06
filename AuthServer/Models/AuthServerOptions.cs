namespace AuthServer.Models;

// AuthServer の動作設定 (appsettings.json の "AuthServer" セクション)。
// 有効期限の既定値は SPEC.md §8.1 SEC-07 の推奨値。すべて秒単位で上書きできる。
public sealed class AuthServerOptions
{
    public string Issuer { get; set; } = "http://localhost:5080";

    // アクセストークン。方式 3 (SPEC.md §6.5) ではこの値が失効の反映遅延の上限になるため短くする。
    // リフレッシュトークンのローテーションがあるので、短くしてもクライアントの負担は小さい。
    public int AccessTokenLifetimeSeconds { get; set; } = 900;

    // ID Token。クライアントは受領直後に検証して使い切るため、アクセストークンと同程度で十分。
    public int IdTokenLifetimeSeconds { get; set; } = 900;

    // リフレッシュトークンの有効期限 (ローテーションごとに延びる = 無操作タイムアウト)。
    public int RefreshTokenLifetimeSeconds { get; set; } = 604800;

    // リフレッシュトークンのファミリー絶対期限 (最初の認可からの上限。ローテーションでは延びない)。
    public int RefreshTokenAbsoluteLifetimeSeconds { get; set; } = 2592000;

    // 認可コード。RFC 6749 §4.1.2 は最大 10 分を推奨。方式 B では取得直後に交換するので短くて良い。
    public int AuthorizationCodeLifetimeSeconds { get; set; } = 120;

    // デバイスコード / ユーザーコード (RFC 8628)。ユーザーが別デバイスでコードを入力する時間を確保する。
    public int DeviceCodeLifetimeSeconds { get; set; } = 600;

    // デバイスフローでクライアントがトークンエンドポイントをポーリングする最短間隔 (RFC 8628 §3.2 interval)。
    public int DeviceCodePollIntervalSeconds { get; set; } = 5;

    // JWKS 応答の Cache-Control max-age (秒)。鍵ローテーションの猶予期間より短くすること
    public int JwksCacheMaxAgeSeconds { get; set; } = 3600;

    // 新規署名鍵のアルゴリズム (RS256 | ES256)。自動ローテーションと初期鍵生成で使う。
    public string SigningKeyAlgorithm { get; set; } = "RS256";

    // 署名鍵の自動ローテーション間隔 (日)。0 で自動ローテーション無効 (管理画面からの手動のみ)
    public int SigningKeyRotationDays { get; set; }

    // 事前公開 (2 段階ローテーション) で、新鍵を JWKS に公開してから署名に使い始めるまでの時間 (秒)。
    // JwksCacheMaxAgeSeconds 以上にしないと、キャッシュの古い ResourceServer が新鍵を知らないまま署名が切り替わる。
    public int SigningKeyPrePublishSeconds { get; set; } = 3600;

    // ローテーション後に旧鍵を JWKS に公開し続ける猶予期間 (日)
    public int SigningKeyGraceDays { get; set; } = 7;

    // 期限切れデータのクリーンアップと鍵の自動ローテーションを実行する間隔 (分)
    public int MaintenanceIntervalMinutes { get; set; } = 60;
}
