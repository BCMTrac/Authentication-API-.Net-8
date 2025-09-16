namespace AuthenticationAPI.Exceptions
{
    public class NotFoundException : ApiException
    {
        public NotFoundException(string message = "The requested resource was not found.") 
            : base(message, 404)
        { }
    }
}
