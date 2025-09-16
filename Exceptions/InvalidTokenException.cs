namespace AuthenticationAPI.Exceptions
{
    public class InvalidTokenException : BadRequestException
    {
        public InvalidTokenException(string message = "The provided token is invalid or expired.") 
            : base(message) { }
    }
}
