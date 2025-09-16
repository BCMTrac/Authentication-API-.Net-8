namespace AuthenticationAPI.Exceptions
{
    public class EmailUnconfirmedException : BadRequestException
    {
        public EmailUnconfirmedException(string message = "Your email address has not been confirmed.") 
            : base(message) { }
    }
}
