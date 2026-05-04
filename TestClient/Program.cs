using System.Text.Json;

var authServer = GetArg(args, "--auth") ?? "http://localhost:5051";
var resourceServer = GetArg(args, "--resource") ?? "http://localhost:5132";
var clientId = GetArg(args, "--client-id") ?? "test-client";
var clientSecret = GetArg(args, "--client-secret") ?? "test-secret";
var scope = GetArg(args, "--scope") ?? "api.read";

using var http = new HttpClient();

Console.WriteLine($"AuthServer:     {authServer}");
Console.WriteLine($"ResourceServer: {resourceServer}");
Console.WriteLine($"ClientId:       {clientId}");
Console.WriteLine($"Scope:          {scope}");
Console.WriteLine();

Console.WriteLine("[1] Requesting access token (client_credentials)...");
var tokenResponse = await http.PostAsync(
    $"{authServer.TrimEnd('/')}/connect/token",
    new FormUrlEncodedContent(new Dictionary<string, string>
    {
        ["grant_type"] = "client_credentials",
        ["client_id"] = clientId,
        ["client_secret"] = clientSecret,
        ["scope"] = scope
    }));

var tokenBody = await tokenResponse.Content.ReadAsStringAsync();
if (!tokenResponse.IsSuccessStatusCode)
{
    Console.Error.WriteLine($"Token request failed: {(int)tokenResponse.StatusCode} {tokenResponse.ReasonPhrase}");
    Console.Error.WriteLine(tokenBody);
    return 1;
}

using var doc = JsonDocument.Parse(tokenBody);
var accessToken = doc.RootElement.GetProperty("access_token").GetString()!;
var expiresIn = doc.RootElement.GetProperty("expires_in").GetInt32();
Console.WriteLine($"    Access token (expires in {expiresIn}s): {Truncate(accessToken, 60)}");
Console.WriteLine();

Console.WriteLine("[2] Calling protected resource...");
using var apiRequest = new HttpRequestMessage(HttpMethod.Get, $"{resourceServer.TrimEnd('/')}/api/protected");
apiRequest.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", accessToken);
var apiResponse = await http.SendAsync(apiRequest);
var apiBody = await apiResponse.Content.ReadAsStringAsync();

Console.WriteLine($"    Status: {(int)apiResponse.StatusCode} {apiResponse.ReasonPhrase}");
Console.WriteLine($"    Body:   {apiBody}");

return apiResponse.IsSuccessStatusCode ? 0 : 2;

static string? GetArg(string[] args, string name)
{
    for (var i = 0; i < args.Length - 1; i++)
    {
        if (string.Equals(args[i], name, StringComparison.Ordinal))
        {
            return args[i + 1];
        }
    }
    return null;
}

static string Truncate(string value, int max) =>
    value.Length <= max ? value : value[..max] + "...";
