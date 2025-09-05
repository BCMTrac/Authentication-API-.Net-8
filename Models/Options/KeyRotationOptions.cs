namespace AuthenticationAPI.Models.Options;

public sealed class KeyRotationOptions
{
    public const string SectionName = "KeyRotation";
    // Rotate if the newest active key is older than this many hours
    public int IntervalHours { get; set; } = 24;
    // How many most-recent active keys to keep concurrently valid (overlap window)
    public int OverlapActiveKeyCount { get; set; } = 2;
    // RSA key size when generating asymmetric keys
    public int RsaKeySize { get; set; } = 3072;
}
