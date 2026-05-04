namespace TestClient;

using System.Text.Json;
using System.Text.Json.Serialization;

/// <summary>
/// トークンファイルの読み書き。
/// デフォルトは <c>~/.testclient/tokens.json</c>。
/// </summary>
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

        try
        {
            var json = File.ReadAllText(file);
            return JsonSerializer.Deserialize<TokenStore>(json, JsonOptions);
        }
        catch (Exception ex)
        {
            ConsoleHelper.WriteError($"Failed to read token file: {ex.Message}");
            return null;
        }
    }

    public static void Save(TokenStore store, string? path = null)
    {
        var file = path ?? DefaultPath;
        Directory.CreateDirectory(Path.GetDirectoryName(file)!);
        File.WriteAllText(file, JsonSerializer.Serialize(store, JsonOptions));
    }
}
