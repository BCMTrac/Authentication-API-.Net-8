namespace AuthenticationAPI.Exceptions
{
    public class AccountLockedException : BadRequestException
    {
        public AccountLockedException(string message = "Your account is locked. Please contact support.") 
            : base(message) { }
    }
}
