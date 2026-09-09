namespace AuthServer.Security;

// RFC 6749 §5.1 (SEC-14)
// 「トークン・資格情報・その他の機微な情報を含む応答」には Cache-Control: no-store と Pragma: no-cache を付ける (MUST)。
// 中間キャッシュやブラウザーの履歴にトークンや認可コードが残らないようにするための要件。
// Discovery と JWKS は公開メタデータなので対象外 (JWKS は逆に max-age を付けて再取得を制御している)。
public static class NoStoreExtensions
{
    public static RouteHandlerBuilder RequireNoStore(this RouteHandlerBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);
        return builder.AddEndpointFilter<NoStoreEndpointFilter>();
    }
}

// 応答本文の書き出しが始まる前にヘッダーを設定する。ハンドラーの成否によらず必ず付ける。
internal sealed class NoStoreEndpointFilter : IEndpointFilter
{
    public ValueTask<object?> InvokeAsync(EndpointFilterInvocationContext context, EndpointFilterDelegate next)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(next);

        var headers = context.HttpContext.Response.Headers;
        headers.CacheControl = "no-store";
        headers.Pragma = "no-cache";
        return next(context);
    }
}
