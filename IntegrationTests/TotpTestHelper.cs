using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace IntegrationTests;

internal static class TotpTestHelper
{
    private static readonly char[] Base32Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".ToCharArray();

    public static string GenerateCode(string base32Secret, DateTimeOffset? now = null, int digits = 6, int periodSeconds = 30)
    {
        var key = FromBase32(base32Secret);
        var timestep = (now ?? DateTimeOffset.UtcNow).ToUnixTimeSeconds() / periodSeconds;
        var code = ComputeTotp(key, timestep, digits);
        return code;
    }

    private static string ComputeTotp(byte[] key, long timestep, int digits)
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
        int otp = binaryCode % (int)Math.Pow(10, digits);
        return otp.ToString(new string('0', digits));
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
