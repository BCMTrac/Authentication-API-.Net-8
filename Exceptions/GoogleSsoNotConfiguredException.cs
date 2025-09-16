namespace AuthenticationAPI.Exceptions
{
    public class GoogleSsoNotConfiguredException : ApiException
    {
        public GoogleSsoNotConfiguredException(string message = "Google SSO is not configured on this system.") 
            : base(message, 501) { }
    }
}
