namespace AuthServer.Endpoints;

using System.Globalization;
using System.Net;
using System.Security.Cryptography;
using System.Text;

// 認可応答の返し方 (RFC 6749 §4.1.2 / §4.1.2.1、OAuth 2.0 Form Post Response Mode)。
//   query     : redirect_uri のクエリ文字列にパラメーターを追記して 302 でリダイレクトする (認可コードフローの既定)
//   form_post : 自動送信する HTML フォームで POST する。認可コードが URL 履歴やリファラーに残らない
internal static class AuthorizeResponse
{
    public const string Query = "query";
    public const string FormPost = "form_post";

    public static readonly string[] SupportedResponseModes = [Query, FormPost];

    // 自動送信スクリプト。CSP のハッシュは実際の本文から求めるので、文言を変えてもずれない
    private const string SubmitScript = "document.forms[0].submit();";

    private static readonly string SubmitScriptHash =
        "'sha256-" + Convert.ToBase64String(SHA256.HashData(Encoding.UTF8.GetBytes(SubmitScript))) + "'";

    public static bool IsSupportedResponseMode(string responseMode) =>
        Array.Exists(SupportedResponseModes, m => String.Equals(m, responseMode, StringComparison.Ordinal));

    public static IResult Code(HttpContext context, string redirectUri, string responseMode, string code, string? state) =>
        Render(context, redirectUri, responseMode, BuildParameters(("code", code), ("state", state)));

    public static IResult Error(HttpContext context, string redirectUri, string responseMode, string error, string description, string? state) =>
        Render(context, redirectUri, responseMode, BuildParameters(("error", error), ("error_description", description), ("state", state)));

    private static List<KeyValuePair<string, string>> BuildParameters(params (string Key, string? Value)[] values) =>
        values
            .Where(v => !String.IsNullOrEmpty(v.Value))
            .Select(v => new KeyValuePair<string, string>(v.Key, v.Value!))
            .ToList();

    private static IResult Render(HttpContext context, string redirectUri, string responseMode, IEnumerable<KeyValuePair<string, string>> parameters) =>
        String.Equals(responseMode, FormPost, StringComparison.Ordinal)
            ? RenderFormPost(context, redirectUri, parameters)
            : RenderQuery(redirectUri, parameters);

    // 既存のクエリ文字列は保持したまま追記する (RFC 6749 §3.1.2 は redirect_uri がクエリを持つことを許容する)
    private static IResult RenderQuery(string redirectUri, IEnumerable<KeyValuePair<string, string>> parameters)
    {
        var builder = new UriBuilder(redirectUri);
        var appended = String.Join(
            '&', parameters.Select(p => $"{Uri.EscapeDataString(p.Key)}={Uri.EscapeDataString(p.Value)}"));
        var existing = builder.Query.TrimStart('?');
        builder.Query = String.IsNullOrEmpty(existing) ? appended : existing + "&" + appended;
        return Results.Redirect(builder.Uri.AbsoluteUri);
    }

    private static IResult RenderFormPost(HttpContext context, string redirectUri, IEnumerable<KeyValuePair<string, string>> parameters)
    {
        // 既定の CSP は form-action を 'self' に限っているため、この応答だけ相手先のオリジンを許可する。
        // 自動送信スクリプトもハッシュで個別に許可する (SEC-15)
        var origin = new Uri(redirectUri).GetLeftPart(UriPartial.Authority);
        context.Response.Headers.ContentSecurityPolicy =
            $"default-src 'none'; base-uri 'none'; frame-ancestors 'none'; script-src {SubmitScriptHash}; form-action {origin}";

        var html = new StringBuilder();
        html.Append("<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>Submitting...</title></head>");
        html.Append("<body>");
        html.Append(CultureInfo.InvariantCulture, $"<form method=\"post\" action=\"{WebUtility.HtmlEncode(redirectUri)}\">");
        foreach (var (key, value) in parameters)
        {
            html.Append(
                CultureInfo.InvariantCulture,
                $"<input type=\"hidden\" name=\"{WebUtility.HtmlEncode(key)}\" value=\"{WebUtility.HtmlEncode(value)}\" />");
        }

        html.Append("<noscript><button type=\"submit\">Continue</button></noscript>");
        html.Append(CultureInfo.InvariantCulture, $"</form><script>{SubmitScript}</script></body></html>");
        return Results.Content(html.ToString(), "text/html", Encoding.UTF8);
    }
}
