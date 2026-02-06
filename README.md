# Wardstone C# SDK

Official C# SDK for the [Wardstone](https://wardstone.ai) LLM security API. Detect prompt attacks, content violations, data leakage, and unknown links in text.

## Installation

```bash
dotnet add package Wardstone
```

## Quick Start

```csharp
using Wardstone;

var client = new WardstoneClient("YOUR_API_KEY");

// Scan text for threats
var result = await client.DetectAsync(userInput);

// Check for prompt attacks
if (result.RiskBands.PromptAttack.Level != "Low Risk")
{
    Console.WriteLine("Prompt attack detected");
    Console.WriteLine($"Risk: {result.RiskBands.PromptAttack.Level}");
}
```

## Configuration

```csharp
// Simple: just an API key
var client = new WardstoneClient("YOUR_API_KEY");

// Full configuration
var client = new WardstoneClient(new WardstoneClientOptions
{
    ApiKey = "YOUR_API_KEY",
    BaseUrl = "https://wardstone.ai",
    Timeout = TimeSpan.FromSeconds(30),
    MaxRetries = 2
});

// Environment variable fallback (reads WARDSTONE_API_KEY)
var client = new WardstoneClient();
```

## Usage

### Basic Detection

```csharp
var result = await client.DetectAsync("Hello, how are you?");

Console.WriteLine($"Flagged: {result.Flagged}");
Console.WriteLine($"Prompt Attack: {result.RiskBands.PromptAttack.Level}");
Console.WriteLine($"Content Violation: {result.RiskBands.ContentViolation.Level}");
Console.WriteLine($"Data Leakage: {result.RiskBands.DataLeakage.Level}");
Console.WriteLine($"Unknown Links: {result.RiskBands.UnknownLinks.Level}");
```

### Advanced Options

```csharp
var result = await client.DetectAsync(new DetectRequest("user input")
{
    ScanStrategy = "full-scan",
    IncludeRawScores = true
});

// Access raw scores (paid plans only)
if (result.RawScores != null)
{
    foreach (var score in result.RawScores.Categories)
    {
        Console.WriteLine($"{score.Key}: {score.Value}");
    }
}
```

### Rate Limit Info

```csharp
var result = await client.DetectAsync("test");
Console.WriteLine($"Rate limit: {result.RateLimit.Remaining}/{result.RateLimit.Limit}");
```

### Error Handling

```csharp
using Wardstone.Exceptions;

try
{
    var result = await client.DetectAsync(userInput);
}
catch (AuthenticationException ex)
{
    // Invalid or missing API key (401)
}
catch (RateLimitException ex)
{
    // Rate limit exceeded (429)
    Console.WriteLine($"Retry after: {ex.RetryAfter}s");
}
catch (BadRequestException ex)
{
    // Invalid input (400)
    if (ex.MaxLength.HasValue)
    {
        Console.WriteLine($"Text too long. Max: {ex.MaxLength}");
    }
}
catch (WardstoneException ex)
{
    // Base exception for all SDK errors
    Console.WriteLine($"Error: {ex.Message}");
}
```

## Requirements

- .NET Standard 2.0+ (.NET Framework 4.6.1+, .NET Core 2.0+, .NET 5+)
- Zero runtime dependencies

## License

MIT
