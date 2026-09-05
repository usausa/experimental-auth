using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi;

using ResourceServer.Endpoints;

using Scalar.AspNetCore;

var builder = WebApplication.CreateBuilder(args);

builder.AddServiceDefaults();

builder.Services.AddOpenApi(options =>
{
    options.AddDocumentTransformer((doc, _, _) =>
    {
        doc.Info.Title = "ResourceServer API";
        doc.Info.Version = "v1";
        doc.Info.Description = "OAuth 2.0 Bearer トークンで保護されたリソース API。";
        var components = doc.Components ?? new OpenApiComponents();
        components.SecuritySchemes ??= new Dictionary<string, IOpenApiSecurityScheme>();
        components.SecuritySchemes["Bearer"] = new OpenApiSecurityScheme
        {
            Type = SecuritySchemeType.Http,
            Scheme = "bearer",
            BearerFormat = "JWT",
            Description = "AuthServer から発行された JWT アクセストークンを入力してください。"
        };
        doc.Components = components;
        return Task.CompletedTask;
    });
});

var jwt = builder.Configuration.GetSection("Jwt");
var authority = jwt["Authority"] ?? throw new InvalidOperationException("Jwt:Authority is required");
var audience = jwt["Audience"] ?? throw new InvalidOperationException("Jwt:Audience is required");

// 既定は true (安全側)。開発環境は HTTP 構成のため appsettings.Development.json で false に下げている。
var requireHttps = jwt.GetValue("RequireHttpsMetadata", true);

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
    app.MapOpenApi("/api-docs/{documentName}.json");
    app.MapScalarApiReference("/api-docs", options =>
    {
        options.WithTitle("ResourceServer API")
               .WithOpenApiRoutePattern("/api-docs/{documentName}.json")
               .AddHttpAuthentication("Bearer", scheme => { scheme.Token = string.Empty; });
    });
}

app.UseAuthentication();
app.UseAuthorization();

app.MapProtectedEndpoints();

app.MapDefaultEndpoints();

app.Run();

static bool HasScope(System.Security.Claims.ClaimsPrincipal user, string required)
{
    var scopeClaim = user.FindFirst("scope")?.Value;
    if (String.IsNullOrEmpty(scopeClaim))
    {
        return false;
    }
    foreach (var s in scopeClaim.Split(' ', StringSplitOptions.RemoveEmptyEntries))
    {
        if (String.Equals(s, required, StringComparison.Ordinal))
        {
            return true;
        }
    }
    return false;
}
