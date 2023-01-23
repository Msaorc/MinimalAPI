using System.Security.Claims;
using apiwithjwt;
using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using apiwithjwt.Models;
using apiwithjwt.Repositories;
using apiwithjwt.Services;

var builder = WebApplication.CreateBuilder(args);
var key = Encoding.ASCII.GetBytes(Settings.Secret);
builder.Services.AddAuthentication(x => {
    x.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    x.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
}).AddJwtBearer(x => {
    x.RequireHttpsMetadata = false;
    x.SaveToken = true;
    x.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = new SymmetricSecurityKey(key),
        ValidateIssuer = false,
        ValidateAudience = false
    };
});

builder.Services.AddAuthorization(options =>{
    options.AddPolicy("Admin", policy => policy.RequireRole("manager"));
    options.AddPolicy("Employee", policy => policy.RequireRole("employee"));
});


var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();
app.MapPost("/login", (User model) =>
{
    var user = UserRepository.Get(model.UserName, model.PassWord);

    if (user == null)
    {
        return Results.NotFound(new {message = "Invalid username or password"});
    }

    var token = TokenService.GenerateToken(user);

    user.PassWord = "";

    return Results.Ok(new
    {
        user = user,
        token = token
    });
});

app.MapGet("/anonymous", () =>
{
    Results.Ok("anonymousMethod");
}).AllowAnonymous();

app.MapGet("/authenticated", (ClaimsPrincipal user) =>
{
    Results.Ok(new { message = $"Autenticated as {user.Identity.Name}"});
}).RequireAuthorization();

app.MapGet("/employee", (ClaimsPrincipal user) =>
{
    Results.Ok(new
    {
        message = $"Autenticated as {user.Identity.Name}"
    });
}).RequireAuthorization("Employee");

app.MapGet("/manager", (ClaimsPrincipal user) =>
{
    Results.Ok(new
    {
        message = $"Autenticated as {user.Identity.Name}"
    });
}).RequireAuthorization("Admin");

app.Run();
