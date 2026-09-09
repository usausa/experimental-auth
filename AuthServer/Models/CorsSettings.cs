namespace AuthServer.Models;

// CORS (SEC-10)。ブラウザー上のクライアント (SPA) からプロトコルエンドポイントを呼び出せるオリジン。
// 空なら CORS 応答ヘッダーを一切返さない (Discovery / JWKS は公開メタデータとして常に任意オリジンを許可する)。
public sealed class CorsSettings
{
    public IList<string> AllowedOrigins { get; } = [];
}
