namespace AuthenticationAPI.Exceptions
{
    public class BadRequestException : ApiException
    {
        public BadRequestException(string message = "The request was invalid.") 
            : base(message, 400) 
        { }
    }
}
