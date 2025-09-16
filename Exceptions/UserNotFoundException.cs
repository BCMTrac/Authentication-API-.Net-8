namespace AuthenticationAPI.Exceptions
{
    public class UserNotFoundException : NotFoundException
    {
        public UserNotFoundException(string message = "User not found.") 
            : base(message) { }
    }
}
