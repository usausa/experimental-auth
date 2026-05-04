namespace TestClient;

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
}
