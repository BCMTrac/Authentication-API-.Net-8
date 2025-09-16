namespace AuthenticationAPI.Exceptions
{
    public class StaleMfaCodeException : BadRequestException
    {
        public StaleMfaCodeException(string message = "The provided MFA code is stale. Please generate a new one.") 
            : base(message) { }
    }
}
