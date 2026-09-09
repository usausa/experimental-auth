namespace AuthServer.Models;

// 管理者が定義するカスタムクレーム。値はユーザーごとに user_claims に保存する。
public sealed class ClaimDefinition
{
    public string ClaimType { get; set; } = default!;
    public string? Description { get; set; }

    // string | number | boolean | json
    public string ValueType { get; set; } = "string";

    // このスコープが付与されたときだけ出力する。NULL なら常に出力
    public string? RequiredScope { get; set; }

    public bool InAccessToken { get; set; }
    public bool InIdToken { get; set; } = true;
    public bool InUserInfo { get; set; } = true;
    public DateTime CreatedAt { get; set; }
    public DateTime UpdatedAt { get; set; }
}

public sealed class UserClaim
{
    public string UserId { get; set; } = default!;
    public string ClaimType { get; set; } = default!;
    public string Value { get; set; } = default!;
    public DateTime UpdatedAt { get; set; }
}
