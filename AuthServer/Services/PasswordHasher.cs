namespace AuthServer.Services;

using System.Security.Cryptography;

/// <summary>
/// PBKDF2-SHA256 ベースのパスワード/シークレットハッシュ。
/// 形式: <c>{iterations}.{saltBase64}.{hashBase64}</c>
/// </summary>
public static class PasswordHasher
{
    private const int SaltSize = 16;
    private const int HashSize = 32;
    private const int Iterations = 600_000;

    public static string Hash(string secret)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(secret);
        var salt = RandomNumberGenerator.GetBytes(SaltSize);
        var hash = Rfc2898DeriveBytes.Pbkdf2(secret, salt, Iterations, HashAlgorithmName.SHA256, HashSize);
        return $"{Iterations}.{Convert.ToBase64String(salt)}.{Convert.ToBase64String(hash)}";
    }

    public static bool Verify(string secret, string hashed)
    {
        if (string.IsNullOrEmpty(secret) || string.IsNullOrEmpty(hashed))
        {
            return false;
        }

        var parts = hashed.Split('.');
        if (parts.Length != 3 ||
            !int.TryParse(parts[0], out var iter) ||
            !TryFromBase64(parts[1], out var salt) ||
            !TryFromBase64(parts[2], out var expected))
        {
            return false;
        }

        var actual = Rfc2898DeriveBytes.Pbkdf2(secret, salt, iter, HashAlgorithmName.SHA256, expected.Length);
        return CryptographicOperations.FixedTimeEquals(actual, expected);
    }

    private static bool TryFromBase64(string value, out byte[] bytes)
    {
        try
        {
            bytes = Convert.FromBase64String(value);
            return true;
        }
        catch (FormatException)
        {
            bytes = [];
            return false;
        }
    }
}
