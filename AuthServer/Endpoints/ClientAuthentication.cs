namespace AuthServer.Endpoints;

using System.Net.Http.Headers;
using System.Text;

// クライアント認証情報の取り出し (RFC 6749 §2.3.1)。
// client_secret_basic (Authorization: Basic) を優先し、なければ client_secret_post (フォーム) を使う。
// Token / Revocation / Introspection の各エンドポイントで共用する。
public static class ClientAuthentication
{
    public static (string ClientId, string? Secret) ResolveCredentials(HttpContext context, IFormCollection form)
    {
        var authHeader = context.Request.Headers.Authorization.ToString();
        if (!String.IsNullOrEmpty(authHeader) &&
            AuthenticationHeaderValue.TryParse(authHeader, out var parsed) &&
            String.Equals(parsed.Scheme, "Basic", StringComparison.OrdinalIgnoreCase) &&
            !String.IsNullOrEmpty(parsed.Parameter))
        {
            try
            {
                var decoded = Encoding.UTF8.GetString(Convert.FromBase64String(parsed.Parameter));
                var idx = decoded.IndexOf(':', StringComparison.Ordinal);
                if (idx >= 0)
                {
                    var id = Uri.UnescapeDataString(decoded[..idx]);
                    var secret = Uri.UnescapeDataString(decoded[(idx + 1)..]);
                    return (id, secret);
                }
            }
            catch (FormatException)
            {
                // Base64 として不正な場合はフォームパラメーターにフォールバックする
            }
        }

        return (form["client_id"].ToString(), form["client_secret"].ToString());
    }
}
