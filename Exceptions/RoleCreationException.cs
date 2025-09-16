namespace AuthenticationAPI.Exceptions
{
    public class RoleCreationException : ApiException
    {
        public RoleCreationException(string message = "Failed to create role.") 
            : base(message, 500) { }
    }
}
