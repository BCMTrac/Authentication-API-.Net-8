namespace AuthenticationAPI.Exceptions
{
    public class SubdomainTakenException : BadRequestException
    {
        public SubdomainTakenException(string message = "The requested subdomain is already in use.") 
            : base(message) { }
    }
}
