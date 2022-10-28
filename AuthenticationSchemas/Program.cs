using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.Extensions.Options;
using System.Security.Claims;
using System.Text.Encodings.Web;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuthentication()
    .AddScheme<CookieAuthenticationOptions, VisitorAuthHandler>("visitor", options => { })
    .AddCookie("local")
    .AddCookie("admin-cookie")
    .AddOAuth("external-admin", options =>
    {
        options.SignInScheme = "admin-cookie";

        options.ClientId = "id";
        options.ClientSecret = "secret";

        options.AuthorizationEndpoint = "https://oauth.mocklab.io/oauth/authorize";
        options.TokenEndpoint = "https://oauth.mocklab.io/oauth/token";
        options.UserInformationEndpoint = "https://oauth.mocklab.io/userinfo";
        options.CallbackPath = "/cb-admin";

        options.Scope.Add("profile");
        options.SaveTokens = true;
    });

builder.Services.AddAuthorization(configure =>
{
    configure.AddPolicy("customer", policy =>
    {
        policy.AddAuthenticationSchemes("admin-cookie", "local", "visitor")
        .RequireAuthenticatedUser();
    });

    configure.AddPolicy("user", policy =>
    {
        policy.AddAuthenticationSchemes("local")
        .RequireAuthenticatedUser();
    });
});

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/", async ctx =>
{
    await ctx.Response.WriteAsync(string.Join('\n', ctx.User.Identities.Select(t => t.AuthenticationType)));
}).RequireAuthorization("customer");

app.MapGet("/login-local", async ctx =>
{
    var claims = new List<Claim>();
    claims.Add(new Claim("usr", "emil"));
    var identity = new ClaimsIdentity(claims, "local");
    var user = new ClaimsPrincipal(identity);

    await ctx.SignInAsync("local", user);
});

app.MapGet("/login-admin", async ctx =>
{
    await ctx.ChallengeAsync("external-admin", new AuthenticationProperties()
    {
        RedirectUri = "/"
    });
}).RequireAuthorization("user");


app.Run();

public class VisitorAuthHandler : CookieAuthenticationHandler
{
    public VisitorAuthHandler(IOptionsMonitor<CookieAuthenticationOptions> options,
                              ILoggerFactory logger,
                              UrlEncoder encoder,
                              ISystemClock clock) : base(options, logger, encoder, clock) { }

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {

        var result = await base.HandleAuthenticateAsync();
        if (result.Succeeded)
        {
            return result;
        }

        var claims = new List<Claim>();
        claims.Add(new Claim("usr", "emil"));
        var identity = new ClaimsIdentity(claims, "visitor");
        var user = new ClaimsPrincipal(identity);

        await Context.SignInAsync("visitor", user);

        return AuthenticateResult.Success(new AuthenticationTicket(user, "visitor"));
    }
}