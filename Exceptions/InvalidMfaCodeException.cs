namespace AuthenticationAPI.Exceptions
{
    public class InvalidMfaCodeException : BadRequestException
    {
        public InvalidMfaCodeException(string message = "The provided MFA code is invalid.") 
            : base(message) { }
    }
}
