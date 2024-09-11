namespace UserManagementTest.Models
{
    public class LoginResponse
    {
        public Token access_Token { get; set; }
        public string? refresh_token { get; set; }
    }
    public class Token
    {
        public string? token { get; set; }
        public DateTime? expires_In { get; set; }
        public DateTime? current_Time { get; set; }
    }
    public class UserResponse
    {
        public int Id { get; set; }
        public string? Username { get; set; }
        public string? Password { get; set; }
        public string? Role { get; set; }
    }

    public class UserConstants
    {
        public static List<UserResponse> Users = new()
            {
                    new UserResponse(){ Username="string",Password="string",Role="Weather",Id=1}
            };
    }
}
