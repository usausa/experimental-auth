using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;

using ResourceServer.Endpoints;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddOpenApi();

var jwt = builder.Configuration.GetSection("Jwt");
var authority = jwt["Authority"] ?? throw new InvalidOperationException("Jwt:Authority is required");
var audience = jwt["Audience"] ?? throw new InvalidOperationException("Jwt:Audience is required");
var requireHttps = jwt.GetValue("RequireHttpsMetadata", false);

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.Authority = authority;
        options.Audience = audience;
        options.RequireHttpsMetadata = requireHttps;
        options.MapInboundClaims = false;
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = authority,
            ValidateAudience = true,
            ValidAudience = audience,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            NameClaimType = "sub",
            RoleClaimType = "role"
        };
    });

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("api.read", policy => policy.RequireAuthenticatedUser().RequireAssertion(ctx => HasScope(ctx.User, "api.read")));
    options.AddPolicy("api.write", policy => policy.RequireAuthenticatedUser().RequireAssertion(ctx => HasScope(ctx.User, "api.write")));
});

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

app.UseAuthentication();
app.UseAuthorization();

app.MapProtectedEndpoints();

app.Run();

static bool HasScope(System.Security.Claims.ClaimsPrincipal user, string required)
{
    var scopeClaim = user.FindFirst("scope")?.Value;
    if (string.IsNullOrEmpty(scopeClaim))
    {
        return false;
    }
    foreach (var s in scopeClaim.Split(' ', StringSplitOptions.RemoveEmptyEntries))
    {
        if (string.Equals(s, required, StringComparison.Ordinal))
        {
            return true;
        }
    }
    return false;
}
