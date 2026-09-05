namespace TestClient;

internal static class CommandOptionHelper
{
    // 選択肢オプションを正規化する。未指定なら既定値、許容値に一致 (大文字小文字無視) すれば正規形、それ以外は null。
    public static string? NormalizeChoice(string? value, string defaultValue, string[] allowed)
    {
        if (String.IsNullOrEmpty(value))
        {
            return defaultValue;
        }

        return Array.Find(allowed, a => String.Equals(a, value, StringComparison.OrdinalIgnoreCase));
    }
}
