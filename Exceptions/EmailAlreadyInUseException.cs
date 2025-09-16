namespace AuthenticationAPI.Exceptions
{
    public class EmailAlreadyInUseException : BadRequestException
    {
        public EmailAlreadyInUseException(string message = "This email address is already in use.") 
            : base(message) { }
    }
}
