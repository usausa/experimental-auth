namespace TestClient;

using System.Text.Json;
using System.Text.Json.Serialization;

public static class TokenFile
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    public static string DefaultPath =>
        Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            ".testclient",
            "tokens.json");

    public static TokenStore? Load(string? path = null)
    {
        var file = path ?? DefaultPath;
        if (!File.Exists(file))
        {
            return null;
        }

        var json = File.ReadAllText(file);
        return JsonSerializer.Deserialize<TokenStore>(json, JsonOptions);
    }

    public static void Save(TokenStore store, string? path = null)
    {
        var file = path ?? DefaultPath;
        Directory.CreateDirectory(Path.GetDirectoryName(file)!);
        File.WriteAllText(file, JsonSerializer.Serialize(store, JsonOptions));
    }
}
