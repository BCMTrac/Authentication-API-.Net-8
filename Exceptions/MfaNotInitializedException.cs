namespace AuthenticationAPI.Exceptions
{
    public class MfaNotInitializedException : BadRequestException
    {
        public MfaNotInitializedException(string message = "Multi-factor authentication is not initialized for this account.") 
            : base(message) { }
    }
}
