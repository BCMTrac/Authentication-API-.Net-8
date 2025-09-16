namespace AuthenticationAPI.Exceptions
{
    public class TenantCreationException : ApiException
    {
        public TenantCreationException(string message = "Failed to create tenant.") 
            : base(message, 500) { }
    }
}
