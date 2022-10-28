using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.DataProtection;
using System.Security.Claims;

const string AuthSchema = "cookie";
const string AuthSchema2 = "cookie2";


var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuthentication(AuthSchema)
    .AddCookie(AuthSchema)
    .AddCookie(AuthSchema2);

builder.Services.AddAuthorization(builder =>
{
    builder.AddPolicy("eu passport", pb =>
    {
        pb.RequireAuthenticatedUser()
        .AddAuthenticationSchemes(AuthSchema)
        .RequireClaim("passport_type", "eur");
    });
});

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/unsecure", (HttpContext ctx, IDataProtectionProvider idp) =>
{

    return ctx.User.FindFirst("usr")?.Value ?? "empty";
}).RequireAuthorization("eu passport");

app.MapGet("/denmark", (HttpContext ctx, IDataProtectionProvider idp) =>
{
    return "allowed";
});

app.MapGet("/norway", (HttpContext ctx, IDataProtectionProvider idp) =>
{

    return "allowed";
});

app.MapGet("/sweden", (HttpContext ctx, IDataProtectionProvider idp) =>
{
    return "allowed";
});


app.MapGet("/login", async (HttpContext ctx) =>
{
    var claims = new List<Claim>();
    claims.Add(new Claim("usr", "emil"));
    claims.Add(new Claim("passport_type", "eur"));
    var identity = new ClaimsIdentity(claims, AuthSchema);
    var user = new ClaimsPrincipal(identity);
    await ctx.SignInAsync(user);

}).AllowAnonymous();

app.Run();

public class MyRequirement : IAuthorizationRequirement
{
    public MyRequirement() { }
}

public class RequirementHandler : AuthorizationHandler<MyRequirement>
{
    protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, MyRequirement requirement)
    {
        return Task.CompletedTask;
    }
}