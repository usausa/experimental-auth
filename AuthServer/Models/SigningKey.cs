namespace AuthServer.Models;

public sealed class SigningKey
{
    public string Kid { get; set; } = default!;
    public string Algorithm { get; set; } = "RS256";
    public string PrivateKeyPem { get; set; } = default!;
    public string PublicKeyPem { get; set; } = default!;
    public bool IsActive { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime? ExpiresAt { get; set; }

    // 署名に使い始める時刻。未来なら「予約 (JWKS に公開済み・署名には未使用)」、NULL または過去なら署名に使える
    public DateTime? ActivatesAt { get; set; }
}
