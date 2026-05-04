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
}
