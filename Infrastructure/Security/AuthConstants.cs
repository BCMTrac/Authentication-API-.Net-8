namespace AuthenticationAPI.Infrastructure.Security
{
    public static class AuthConstants
    {
        public static class ClaimTypes
        {
            public const string TokenVersion = "token_version";
            public const string Amr = "amr";
            public const string SessionId = "sid";
        }

        public static class Policies
        {
            public const string Mfa = "mfa";
        }

        public static class TokenProviders
        {
            public const string MagicLink = "magic-login";
        }

        public static class AmrValues
        {
            public const string Mfa = "mfa";
        }
    }
}
