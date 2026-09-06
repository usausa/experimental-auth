namespace TestClient;

using System.Text.Json;

internal static class ConsoleHelper
{
    public static void WriteError(string message)
    {
        var prev = Console.ForegroundColor;
        Console.ForegroundColor = ConsoleColor.Red;
        Console.Error.WriteLine(message);
        Console.ForegroundColor = prev;
    }

    public static void WriteSuccess(string message)
    {
        var prev = Console.ForegroundColor;
        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine(message);
        Console.ForegroundColor = prev;
    }

    public static void WriteInfo(string label, string value)
    {
        Console.Write($"  {label}: ");
        var prev = Console.ForegroundColor;
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine(value);
        Console.ForegroundColor = prev;
    }

    public static string Truncate(string value, int max) =>
        value.Length <= max ? value : value[..max] + "...";

    public static void BeginProgress(string message) => Console.Write(message + " ");

    // JWT のペイロード (第 2 セグメント) を base64url デコードしてクレームを表示する。署名検証は行わない。
    public static void PrintJwtClaims(string jwt)
    {
        var parts = jwt.Split('.');
        if (parts.Length != 3)
        {
            return;
        }

        var payload = parts[1].Replace('-', '+').Replace('_', '/');
        payload = payload.PadRight(payload.Length + ((4 - (payload.Length % 4)) % 4), '=');

        try
        {
            using var doc = JsonDocument.Parse(Convert.FromBase64String(payload));
            foreach (var property in doc.RootElement.EnumerateObject())
            {
                Console.WriteLine($"    {property.Name,-18}: {property.Value.GetRawText()}");
            }
        }
        catch (FormatException)
        {
            WriteError("JWT payload could not be decoded.");
        }
        catch (JsonException)
        {
            WriteError("JWT payload is not valid JSON.");
        }
    }
}
