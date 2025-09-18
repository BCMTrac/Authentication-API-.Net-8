namespace AuthenticationAPI.Infrastructure.Security
{
    public static class AuthConstants
    {
        public static class ClaimTypes
        {
            public const string TokenVersion = "token_version";
            public const string Amr = "amr";
            public const string SessionId = "sid";
            public const string SelectedRole = "bcm:selected_role";
            public const string SelectedScheme = "bcm:selected_scheme";
        }

        public static class Policies
        {
            public const string Mfa = "mfa";
        }

        public static class AmrValues
        {
            public const string Mfa = "mfa";
        }
    }
}
