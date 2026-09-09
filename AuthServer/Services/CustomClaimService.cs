namespace AuthServer.Services;

using System.Globalization;
using System.Text.Json;
using System.Text.RegularExpressions;

using AuthServer.Database;
using AuthServer.Models;

using Dapper;

// カスタムクレームの定義とユーザーごとの値を管理し、トークン発行時に出力先 (アクセストークン / ID Token / UserInfo) ごとの
// 型付きクレーム集合へ解決する。予約済みのクレーム名 (iss, sub, ... および標準プロフィールクレーム) は定義できない。
public sealed partial class CustomClaimService(DbConnectionFactory dbFactory)
{
    public const string TypeString = "string";
    public const string TypeNumber = "number";
    public const string TypeBoolean = "boolean";
    public const string TypeJson = "json";

    public static readonly IReadOnlyList<string> ValueTypes = [TypeString, TypeNumber, TypeBoolean, TypeJson];

    private static readonly HashSet<string> ReservedClaimTypes = new(
    [
        "iss", "sub", "aud", "exp", "iat", "nbf", "jti", "scope", "client_id", "username", "azp", "nonce",
        "auth_time", "amr", "acr", "at_hash", "c_hash", "typ", "alg", "kid", "cnf",
        "name", "given_name", "family_name", "middle_name", "nickname", "preferred_username", "profile", "picture",
        "website", "email", "email_verified", "gender", "birthdate", "zoneinfo", "locale", "phone_number",
        "phone_number_verified", "address", "updated_at"
    ],
    StringComparer.OrdinalIgnoreCase);

    private const string DefinitionColumns = """
        claim_type AS ClaimType, description AS Description, value_type AS ValueType, required_scope AS RequiredScope,
        in_access_token AS InAccessToken, in_id_token AS InIdToken, in_userinfo AS InUserInfo,
        created_at AS CreatedAt, updated_at AS UpdatedAt
        """;

    // クレーム名の検証。問題があればメッセージ、なければ null。
    public static string? ValidateClaimType(string? claimType)
    {
        if (String.IsNullOrWhiteSpace(claimType))
        {
            return "Claim type is required.";
        }

        if (!ClaimTypePattern().IsMatch(claimType))
        {
            return "Claim type must start with a letter and contain only letters, digits, '_', '.', ':', '/' or '-' (max 128).";
        }

        if (ReservedClaimTypes.Contains(claimType))
        {
            return $"'{claimType}' is a reserved claim type.";
        }

        return null;
    }

    // 保存値が value_type として解釈できるかを検証する。問題があればメッセージ、なければ null。
    public static string? ValidateValue(string valueType, string value)
    {
        try
        {
            ConvertValue(valueType, value);
            return null;
        }
        catch (FormatException ex)
        {
            return ex.Message;
        }
        catch (JsonException ex)
        {
            return "Invalid JSON: " + ex.Message;
        }
    }

    // 保存値 (文字列) を value_type に従って型付きの値へ変換する。トークンや UserInfo の JSON にそのまま出力できる。
    public static object ConvertValue(string valueType, string value)
    {
        switch (valueType)
        {
            case TypeNumber:
                if (Int64.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var l))
                {
                    return l;
                }

                if (Double.TryParse(value, NumberStyles.Float, CultureInfo.InvariantCulture, out var d))
                {
                    return d;
                }

                throw new FormatException($"'{value}' is not a number.");
            case TypeBoolean:
                if (Boolean.TryParse(value, out var b))
                {
                    return b;
                }

                throw new FormatException($"'{value}' is not true/false.");
            case TypeJson:
                return JsonSerializer.Deserialize<JsonElement>(value);
            default:
                return value;
        }
    }

    public async Task<IReadOnlyList<ClaimDefinition>> QueryDefinitionListAsync()
    {
        await using var connection = dbFactory.OpenConnection();
        var rows = await connection.QueryAsync<ClaimDefinition>(
            $"SELECT {DefinitionColumns} FROM claim_definitions ORDER BY claim_type");
        return rows.ToList();
    }

    public async Task<ClaimDefinition?> QueryDefinitionAsync(string claimType)
    {
        await using var connection = dbFactory.OpenConnection();
        return await connection.QueryFirstOrDefaultAsync<ClaimDefinition>(
            $"SELECT {DefinitionColumns} FROM claim_definitions WHERE claim_type = @ClaimType",
            new { ClaimType = claimType });
    }

    // 定義を追加または更新する (claim_type がキー)。
    public async Task SaveDefinitionAsync(ClaimDefinition definition)
    {
        ArgumentNullException.ThrowIfNull(definition);
        var now = DateTime.UtcNow.ToString("o", CultureInfo.InvariantCulture);
        await using var connection = dbFactory.OpenConnection();
        await connection.ExecuteAsync("""
            INSERT INTO claim_definitions
                (claim_type, description, value_type, required_scope, in_access_token, in_id_token, in_userinfo, created_at, updated_at)
            VALUES
                (@ClaimType, @Description, @ValueType, @RequiredScope, @InAccessToken, @InIdToken, @InUserInfo, @Now, @Now)
            ON CONFLICT(claim_type) DO UPDATE SET
                description = excluded.description,
                value_type = excluded.value_type,
                required_scope = excluded.required_scope,
                in_access_token = excluded.in_access_token,
                in_id_token = excluded.in_id_token,
                in_userinfo = excluded.in_userinfo,
                updated_at = excluded.updated_at
            """,
            new
            {
                definition.ClaimType,
                definition.Description,
                definition.ValueType,
                RequiredScope = String.IsNullOrWhiteSpace(definition.RequiredScope) ? null : definition.RequiredScope.Trim(),
                InAccessToken = definition.InAccessToken ? 1 : 0,
                InIdToken = definition.InIdToken ? 1 : 0,
                InUserInfo = definition.InUserInfo ? 1 : 0,
                Now = now
            });
    }

    // 定義とそのユーザー値をまとめて削除する。
    public async Task DeleteDefinitionAsync(string claimType)
    {
        await using var connection = dbFactory.OpenConnection();
        await connection.ExecuteAsync("DELETE FROM user_claims WHERE claim_type = @ClaimType", new { ClaimType = claimType });
        await connection.ExecuteAsync("DELETE FROM claim_definitions WHERE claim_type = @ClaimType", new { ClaimType = claimType });
    }

    public async Task<IReadOnlyList<UserClaim>> QueryUserClaimListAsync(string userId)
    {
        await using var connection = dbFactory.OpenConnection();
        var rows = await connection.QueryAsync<UserClaim>(
            "SELECT user_id AS UserId, claim_type AS ClaimType, value AS Value, updated_at AS UpdatedAt FROM user_claims WHERE user_id = @UserId ORDER BY claim_type",
            new { UserId = userId });
        return rows.ToList();
    }

    // 値を保存する。空文字 / null なら削除する。
    public async Task SetUserClaimAsync(string userId, string claimType, string? value)
    {
        await using var connection = dbFactory.OpenConnection();
        if (String.IsNullOrWhiteSpace(value))
        {
            await connection.ExecuteAsync(
                "DELETE FROM user_claims WHERE user_id = @UserId AND claim_type = @ClaimType",
                new { UserId = userId, ClaimType = claimType });
            return;
        }

        await connection.ExecuteAsync("""
            INSERT INTO user_claims (user_id, claim_type, value, updated_at)
            VALUES (@UserId, @ClaimType, @Value, @Now)
            ON CONFLICT(user_id, claim_type) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
            """,
            new { UserId = userId, ClaimType = claimType, Value = value.Trim(), Now = DateTime.UtcNow.ToString("o", CultureInfo.InvariantCulture) });
    }

    // ユーザーの値と定義を突き合わせ、付与スコープで許可されるものを出力先ごとに型付きで返す。
    public async Task<CustomClaimSet> ResolveForUserAsync(string userId, IReadOnlyList<string> grantedScopes)
    {
        await using var connection = dbFactory.OpenConnection();
        var rows = await connection.QueryAsync<dynamic>("""
            SELECT d.claim_type, d.value_type, d.required_scope, d.in_access_token, d.in_id_token, d.in_userinfo, u.value
            FROM user_claims u
            JOIN claim_definitions d ON d.claim_type = u.claim_type
            WHERE u.user_id = @UserId
            """, new { UserId = userId });

        var access = new Dictionary<string, object>(StringComparer.Ordinal);
        var id = new Dictionary<string, object>(StringComparer.Ordinal);
        var userInfo = new Dictionary<string, object>(StringComparer.Ordinal);
        foreach (var row in rows)
        {
            var requiredScope = row.required_scope is null or DBNull ? null : (string?)row.required_scope;
            if ((requiredScope is not null) && !grantedScopes.Contains(requiredScope, StringComparer.Ordinal))
            {
                continue;
            }

            object value;
            try
            {
                value = ConvertValue((string)row.value_type, (string)row.value);
            }
            catch (FormatException)
            {
                continue;
            }
            catch (JsonException)
            {
                continue;
            }

            var claimType = (string)row.claim_type;
            if ((long)row.in_access_token != 0)
            {
                access[claimType] = value;
            }

            if ((long)row.in_id_token != 0)
            {
                id[claimType] = value;
            }

            if ((long)row.in_userinfo != 0)
            {
                userInfo[claimType] = value;
            }
        }

        return new CustomClaimSet(access, id, userInfo);
    }

    // 定義に含まれる required_scope の一覧 (Discovery の scopes_supported に載せる)。
    public async Task<IReadOnlyList<string>> QueryRequiredScopesAsync()
    {
        await using var connection = dbFactory.OpenConnection();
        var rows = await connection.QueryAsync<string>(
            "SELECT DISTINCT required_scope FROM claim_definitions WHERE required_scope IS NOT NULL AND required_scope <> '' ORDER BY required_scope");
        return rows.ToList();
    }

    [GeneratedRegex("^[A-Za-z][A-Za-z0-9_.:/-]{0,127}$")]
    private static partial Regex ClaimTypePattern();
}

// 出力先ごとの型付きクレーム集合。値は string / long / double / bool / JsonElement のいずれか。
public sealed record CustomClaimSet(
    IReadOnlyDictionary<string, object> AccessToken,
    IReadOnlyDictionary<string, object> IdToken,
    IReadOnlyDictionary<string, object> UserInfo)
{
    public static CustomClaimSet Empty { get; } = new(
        new Dictionary<string, object>(), new Dictionary<string, object>(), new Dictionary<string, object>());
}
