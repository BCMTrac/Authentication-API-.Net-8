using System;
using System.Text;
using System.Text.Json;

namespace IntegrationTests;

internal static class JwtTestHelper
{
    public static JsonElement ReadHeader(string jwt)
    {
        var parts = jwt.Split('.');
        if (parts.Length < 2) throw new ArgumentException("Invalid JWT");
        var json = Base64UrlDecode(parts[0]);
        using var doc = JsonDocument.Parse(json);
        return doc.RootElement.Clone();
    }

    public static JsonElement ReadPayload(string jwt)
    {
        var parts = jwt.Split('.');
        if (parts.Length < 2) throw new ArgumentException("Invalid JWT");
        var json = Base64UrlDecode(parts[1]);
        using var doc = JsonDocument.Parse(json);
        return doc.RootElement.Clone();
    }

    private static string Base64UrlDecode(string input)
    {
        string s = input.Replace('-', '+').Replace('_', '/');
        switch (s.Length % 4)
        {
            case 2: s += "=="; break;
            case 3: s += "="; break;
        }
        var bytes = Convert.FromBase64String(s);
        return Encoding.UTF8.GetString(bytes);
    }
}
