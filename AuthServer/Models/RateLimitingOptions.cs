namespace AuthServer.Models;

// レート制限 (SEC-09)。クライアント IP ごとの固定ウィンドウ。PermitLimit を 0 以下にすると当該ポリシーは無制限になる。
public sealed class RateLimitingOptions
{
    public bool Enabled { get; set; } = true;

    // ウィンドウ長 (秒)
    public int WindowSeconds { get; set; } = 60;

    // /connect/authorize (ユーザーの資格情報を受け取る) 向け。パスワード総当たり対策として厳しめにする
    public int AuthenticationPermitLimit { get; set; } = 10;

    // トークン系エンドポイント (token / device authorize / revoke / introspect / userinfo) 向け
    public int TokenPermitLimit { get; set; } = 60;
}
