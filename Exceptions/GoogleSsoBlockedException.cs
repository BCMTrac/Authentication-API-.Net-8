namespace AuthenticationAPI.Exceptions
{
    public class GoogleSsoBlockedException : BadRequestException
    {
        public GoogleSsoBlockedException(string message = "Google SSO is blocked for your domain.") 
            : base(message) { }
    }
}
