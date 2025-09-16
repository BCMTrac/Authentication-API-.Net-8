namespace AuthenticationAPI.Exceptions
{
    public class TenantAdminCreationException : ApiException
    {
        public TenantAdminCreationException(string message = "Failed to create tenant administrator.") 
            : base(message, 500) { }
    }
}
