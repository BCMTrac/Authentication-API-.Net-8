namespace AuthenticationAPI.Models.Options;

public class SmtpOptions
{
    public const string SectionName = "Smtp";
    public string Host { get; set; } = string.Empty;
    public int Port { get; set; } = 25;
    public string From { get; set; } = string.Empty;
    public string FromName { get; set; } = string.Empty;
    public bool UseSsl { get; set; } = false;
    public string? Username { get; set; }
    public string? Password { get; set; }
}
