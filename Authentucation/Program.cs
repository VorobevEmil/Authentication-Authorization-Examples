using Microsoft.AspNetCore.DataProtection;
using System.Security.Claims;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddDataProtection();
builder.Services.AddHttpContextAccessor();
builder.Services.AddScoped<AuthService>();

var app = builder.Build();

app.Use((ctx, next) =>
{
    var authCookie = ctx.Request.Headers.Cookie.FirstOrDefault(x => x.StartsWith("auth="));
    if (authCookie != null)
    {
        var idp = ctx.RequestServices.GetDataProtectionProvider();
        var protector = idp.CreateProtector("auth-cookie");

        var protectedPayload = authCookie.Split('=').Last();
        var payload = protector.Unprotect(protectedPayload);
        var parts = payload.Split(':');
        var key = parts[0];
        var value = parts[1];

        var claims = new List<Claim>();
        claims.Add(new Claim(key, value));
        var identity = new ClaimsIdentity(claims);
        ctx.User = new ClaimsPrincipal(identity);

    }


    return next();
});

app.MapGet("/username", (HttpContext ctx, IDataProtectionProvider idp) =>
{
    return ctx.User.FindFirst("usr")?.Value ?? StatusCodes.Status401Unauthorized.ToString();
});

app.MapGet("/login", (AuthService authService) =>
{
    authService.SignIn();
    return "OK";
});

app.Run();

public class AuthService
{
    private readonly IDataProtectionProvider _idp;
    private readonly IHttpContextAccessor _accessor;

    public AuthService(IDataProtectionProvider idp, IHttpContextAccessor accessor)
    {
        _idp = idp;
        _accessor = accessor;
    }

    public void SignIn()
    {
        var protector = _idp.CreateProtector("auth-cookie");


        _accessor.HttpContext!.Response.Headers["set-cookie"] = $"auth={protector.Protect("usr:Emil")}";
    }
}