using System;
using ComplianceMonitor.Api.Middleware;
using ComplianceMonitor.Infrastructure;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using ComplianceMonitor.Infrastructure.Data;
using ComplianceMonitor.Infrastructure.Background;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container
builder.Services.AddControllers();

// Configure swagger
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new() { Title = "Compliance Monitor API", Version = "v1" });
});

// Configure CORS
builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(policy =>
    {
        policy.WithOrigins(builder.Configuration.GetSection("AllowedOrigins").Get<string[]>() ?? new[] { "http://localhost:3000" })
            .AllowAnyMethod()
            .AllowAnyHeader();
    });
});

// Add application services
builder.Services.AddApplication(builder.Configuration);

// Add infrastructure services
builder.Services.AddInfrastructure(builder.Configuration);

// Configure background service options
builder.Services.Configure<ScanBackgroundServiceOptions>(builder.Configuration.GetSection("BackgroundService"));

// Build the app
var app = builder.Build();

// Configure the HTTP request pipeline
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();

    // Apply database migrations in development
    using (var scope = app.Services.CreateScope())
    {
        var dbContext = scope.ServiceProvider.GetRequiredService<ComplianceDbContext>();
        var logger = scope.ServiceProvider.GetRequiredService<ILogger<Program>>();

        try
        {
            logger.LogInformation("Applying database migrations...");
            dbContext.Database.Migrate();
            logger.LogInformation("Database migrations applied successfully");
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "An error occurred while applying database migrations");
        }
    }
}
else
{
    // Custom exception handler for production
    app.UseExceptionHandler("/error");

    // Enable HTTPS redirection in production
    app.UseHsts();
    app.UseHttpsRedirection();
}

// Use custom exception handling middleware
app.UseMiddleware<ExceptionHandlingMiddleware>();

// Enable CORS
app.UseCors();

app.UseRouting();
app.UseAuthorization();

app.MapControllers();

// Add health check endpoint
app.MapGet("/health", () => "Healthy");

app.Run();
