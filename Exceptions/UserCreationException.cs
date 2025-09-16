namespace AuthenticationAPI.Exceptions
{
    public class UserCreationException : ApiException
    {
        public UserCreationException(string message = "Failed to create user.") 
            : base(message, 500) { }
    }
}
