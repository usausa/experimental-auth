namespace TestClient;

/// <summary>
/// ~/.testclient/tokens.json に保存されるトークン情報。
/// </summary>
public sealed class TokenStore
{
    public string? AccessToken { get; set; }
    public string? RefreshToken { get; set; }
    public string? TokenType { get; set; }
    public int ExpiresIn { get; set; }
    public string? Scope { get; set; }
    public DateTimeOffset IssuedAt { get; set; }

    public DateTimeOffset ExpiresAt => IssuedAt.AddSeconds(ExpiresIn);
    public bool IsExpired => DateTimeOffset.UtcNow >= ExpiresAt;
}
