using System.Security.Cryptography;
using System.Text;

namespace AuthenticationAPI.Services;

public class TotpService : ITotpService
{
    private static readonly char[] Base32Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".ToCharArray();

    public string GenerateSecret()
    {
        Span<byte> buffer = stackalloc byte[20];
        RandomNumberGenerator.Fill(buffer);
        return ToBase32(buffer);
    }

    public string GetOtpAuthUrl(string secret, string userEmail, string issuer)
        => $"otpauth://totp/{Uri.EscapeDataString(issuer)}:{Uri.EscapeDataString(userEmail)}?secret={secret}&issuer={Uri.EscapeDataString(issuer)}&digits=6&period=30&algorithm=SHA1";

    public bool ValidateCode(string secret, string code, out long timeStepMatched)
    {
        timeStepMatched = -1;
        if (code.Length != 6 || !code.All(char.IsDigit)) return false;
        var key = FromBase32(secret);
        var timestep = DateTimeOffset.UtcNow.ToUnixTimeSeconds() / 30;
        // allow +/-1 window
        for (long ts = timestep - 1; ts <= timestep + 1; ts++)
        {
            var expected = ComputeTotp(key, ts);
            if (TimingSafeEquals(expected, code))
            {
                timeStepMatched = ts;
                return true;
            }
        }
        return false;
    }

    private static string ComputeTotp(byte[] key, long timestep)
    {
        Span<byte> msg = stackalloc byte[8];
        for (int i = 7; i >= 0; i--)
        {
            msg[i] = (byte)(timestep & 0xFF);
            timestep >>= 8;
        }
        using var hmac = new HMACSHA1(key);
        var hash = hmac.ComputeHash(msg.ToArray());
        int offset = hash[^1] & 0x0F;
        int binaryCode = ((hash[offset] & 0x7f) << 24) | (hash[offset + 1] << 16) | (hash[offset + 2] << 8) | hash[offset + 3];
        int otp = binaryCode % 1_000_000;
        return otp.ToString("D6");
    }

    private static bool TimingSafeEquals(string a, string b)
    {
        if (a.Length != b.Length) return false;
        int diff = 0;
        for (int i = 0; i < a.Length; i++) diff |= a[i] ^ b[i];
        return diff == 0;
    }

    private static string ToBase32(ReadOnlySpan<byte> data)
    {
        int outputLength = (int)Math.Ceiling(data.Length / 5d) * 8;
        var sb = new StringBuilder(outputLength);
        int bitBuffer = 0; int bitsInBuffer = 0;
        foreach (var b in data)
        {
            bitBuffer = (bitBuffer << 8) | b;
            bitsInBuffer += 8;
            while (bitsInBuffer >= 5)
            {
                int index = (bitBuffer >> (bitsInBuffer - 5)) & 0x1F;
                bitsInBuffer -= 5;
                sb.Append(Base32Chars[index]);
            }
        }
        if (bitsInBuffer > 0)
        {
            int index = (bitBuffer << (5 - bitsInBuffer)) & 0x1F;
            sb.Append(Base32Chars[index]);
        }
        return sb.ToString();
    }

    private static byte[] FromBase32(string s)
    {
        s = s.TrimEnd('=');
        int byteCount = s.Length * 5 / 8;
        byte[] result = new byte[byteCount];
        int bitBuffer = 0; int bitsInBuffer = 0; int pos = 0;
        foreach (var c in s.ToUpperInvariant())
        {
            int val = Array.IndexOf(Base32Chars, c);
            if (val < 0) throw new FormatException("Invalid Base32 char");
            bitBuffer = (bitBuffer << 5) | val;
            bitsInBuffer += 5;
            if (bitsInBuffer >= 8)
            {
                bitsInBuffer -= 8;
                result[pos++] = (byte)((bitBuffer >> bitsInBuffer) & 0xFF);
            }
        }
        if (pos != byteCount) Array.Resize(ref result, pos);
        return result;
    }
}
