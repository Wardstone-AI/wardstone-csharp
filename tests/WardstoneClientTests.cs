using System;
using System.Reflection;
using System.Threading.Tasks;
using Wardstone;
using Wardstone.Exceptions;
using Wardstone.Models;
using Xunit;

namespace Wardstone.Tests
{
    public class WardstoneClientTests
    {
        private const string ValidKey = "wst_test_key_12345678";

        // -----------------------------------------------------------------------
        // Constructor: API key validation
        // -----------------------------------------------------------------------

        [Fact]
        public void ConstructorRequiresApiKey()
        {
            string envKey = Environment.GetEnvironmentVariable("WARDSTONE_API_KEY");
            if (!string.IsNullOrEmpty(envKey))
            {
                // Skip: env var is set, cannot test missing key scenario
                return;
            }
            var ex = Assert.Throws<AuthenticationException>(() => new WardstoneClient(new WardstoneClientOptions()));
            Assert.Contains("API key is required", ex.Message);
        }

        [Fact]
        public void ConstructorRejectsEmptyApiKey()
        {
            var ex = Assert.Throws<AuthenticationException>(() =>
                new WardstoneClient(new WardstoneClientOptions { ApiKey = "" }));
            Assert.Contains("API key is required", ex.Message);
        }

        [Fact]
        public void ConstructorRejectsWhitespaceApiKey()
        {
            var ex = Assert.Throws<AuthenticationException>(() =>
                new WardstoneClient(new WardstoneClientOptions { ApiKey = "   " }));
            Assert.Contains("API key is required", ex.Message);
        }

        [Fact]
        public void ConstructorRejectsShortApiKey()
        {
            var ex = Assert.Throws<AuthenticationException>(() => new WardstoneClient("short"));
            Assert.Contains("too short", ex.Message);
        }

        [Fact]
        public void ConstructorTrimsApiKey()
        {
            var client = new WardstoneClient("  " + ValidKey + "  ");
            Assert.NotNull(client);
            client.Dispose();
        }

        [Fact]
        public void ConstructorAcceptsValidApiKey()
        {
            var client = new WardstoneClient(ValidKey);
            Assert.NotNull(client);
            client.Dispose();
        }

        // -----------------------------------------------------------------------
        // Constructor: base URL validation
        // -----------------------------------------------------------------------

        [Fact]
        public void ConstructorRejectsInvalidBaseUrl()
        {
            var ex = Assert.Throws<WardstoneException>(() =>
                new WardstoneClient(new WardstoneClientOptions { ApiKey = ValidKey, BaseUrl = "not-a-url" }));
            Assert.Contains("Invalid baseUrl", ex.Message);
        }

        [Fact]
        public void ConstructorRejectsFtpBaseUrl()
        {
            var ex = Assert.Throws<WardstoneException>(() =>
                new WardstoneClient(new WardstoneClientOptions { ApiKey = ValidKey, BaseUrl = "ftp://example.com" }));
            Assert.Contains("protocol", ex.Message);
        }

        [Fact]
        public void ConstructorRejectsHttpForNonLocalhost()
        {
            var ex = Assert.Throws<WardstoneException>(() =>
                new WardstoneClient(new WardstoneClientOptions { ApiKey = ValidKey, BaseUrl = "http://example.com" }));
            Assert.Contains("HTTP is only allowed for localhost", ex.Message);
        }

        [Fact]
        public void ConstructorRejectsHttpForLocalhost()
        {
            // "localhost" is rejected to prevent DNS rebinding attacks; only literal IPs (127.0.0.1, [::1]) are allowed
            var ex = Assert.Throws<WardstoneException>(() =>
                new WardstoneClient(new WardstoneClientOptions { ApiKey = ValidKey, BaseUrl = "http://localhost:3000" }));
            Assert.Contains("HTTP is only allowed for localhost", ex.Message);
        }

        [Fact]
        public void ConstructorAllowsHttpFor127001()
        {
            var client = new WardstoneClient(new WardstoneClientOptions { ApiKey = ValidKey, BaseUrl = "http://127.0.0.1:3000" });
            Assert.NotNull(client);
            client.Dispose();
        }

        [Fact]
        public void ConstructorAllowsHttpForIpv6Loopback()
        {
            var client = new WardstoneClient(new WardstoneClientOptions { ApiKey = ValidKey, BaseUrl = "http://[::1]:3000" });
            Assert.NotNull(client);
            client.Dispose();
        }

        [Fact]
        public void ConstructorRejectsHttpForAllInterfaces()
        {
            // 0.0.0.0 is the "all interfaces" address, not loopback; must be rejected
            var ex = Assert.Throws<WardstoneException>(() =>
                new WardstoneClient(new WardstoneClientOptions { ApiKey = ValidKey, BaseUrl = "http://0.0.0.0:3000" }));
            Assert.Contains("HTTP is only allowed for localhost", ex.Message);
        }

        [Fact]
        public void ConstructorRejectsCredentialsInUrl()
        {
            var ex = Assert.Throws<WardstoneException>(() =>
                new WardstoneClient(new WardstoneClientOptions { ApiKey = ValidKey, BaseUrl = "https://user:pass@example.com" }));
            Assert.Contains("credentials", ex.Message);
        }

        [Fact]
        public void ConstructorRejectsQueryStringInUrl()
        {
            var ex = Assert.Throws<WardstoneException>(() =>
                new WardstoneClient(new WardstoneClientOptions { ApiKey = ValidKey, BaseUrl = "https://example.com?foo=bar" }));
            Assert.Contains("query", ex.Message);
        }

        [Fact]
        public void ConstructorRejectsFragmentInUrl()
        {
            var ex = Assert.Throws<WardstoneException>(() =>
                new WardstoneClient(new WardstoneClientOptions { ApiKey = ValidKey, BaseUrl = "https://example.com#frag" }));
            Assert.Contains("fragment", ex.Message);
        }

        // -----------------------------------------------------------------------
        // Constructor: timeout validation
        // -----------------------------------------------------------------------

        [Fact]
        public void ConstructorRejectsZeroTimeout()
        {
            var ex = Assert.Throws<WardstoneException>(() =>
                new WardstoneClient(new WardstoneClientOptions { ApiKey = ValidKey, Timeout = TimeSpan.Zero }));
            Assert.Contains("timeout", ex.Message);
        }

        [Fact]
        public void ConstructorRejectsNegativeTimeout()
        {
            var ex = Assert.Throws<WardstoneException>(() =>
                new WardstoneClient(new WardstoneClientOptions { ApiKey = ValidKey, Timeout = TimeSpan.FromMilliseconds(-1) }));
            Assert.Contains("timeout", ex.Message);
        }

        [Fact]
        public void ConstructorRejectsExcessiveTimeout()
        {
            var ex = Assert.Throws<WardstoneException>(() =>
                new WardstoneClient(new WardstoneClientOptions { ApiKey = ValidKey, Timeout = TimeSpan.FromMilliseconds(400_000) }));
            Assert.Contains("timeout", ex.Message);
        }

        // -----------------------------------------------------------------------
        // Constructor: maxRetries validation
        // -----------------------------------------------------------------------

        [Fact]
        public void ConstructorRejectsNegativeMaxRetries()
        {
            var ex = Assert.Throws<WardstoneException>(() =>
                new WardstoneClient(new WardstoneClientOptions { ApiKey = ValidKey, MaxRetries = -1 }));
            Assert.Contains("maxRetries", ex.Message);
        }

        [Fact]
        public void ConstructorRejectsExcessiveMaxRetries()
        {
            var ex = Assert.Throws<WardstoneException>(() =>
                new WardstoneClient(new WardstoneClientOptions { ApiKey = ValidKey, MaxRetries = 11 }));
            Assert.Contains("maxRetries", ex.Message);
        }

        [Fact]
        public void ConstructorAcceptsZeroMaxRetries()
        {
            var client = new WardstoneClient(new WardstoneClientOptions { ApiKey = ValidKey, MaxRetries = 0 });
            Assert.NotNull(client);
            client.Dispose();
        }

        // -----------------------------------------------------------------------
        // Input validation: detect method
        // -----------------------------------------------------------------------

        [Fact]
        public async Task DetectRejectsNullText()
        {
            var client = new WardstoneClient(ValidKey);
            var ex = await Assert.ThrowsAsync<BadRequestException>(() => client.DetectAsync((string)null));
            Assert.Contains("non-empty string", ex.Message);
            client.Dispose();
        }

        [Fact]
        public async Task DetectRejectsEmptyText()
        {
            var client = new WardstoneClient(ValidKey);
            var ex = await Assert.ThrowsAsync<BadRequestException>(() => client.DetectAsync(""));
            Assert.Contains("non-empty string", ex.Message);
            client.Dispose();
        }

        [Fact]
        public async Task DetectRejectsTooLongText()
        {
            var client = new WardstoneClient(ValidKey);
            string longText = new string('a', 8_000_001);

            var ex = await Assert.ThrowsAsync<BadRequestException>(() => client.DetectAsync(longText));
            Assert.Contains("exceeds maximum length", ex.Message);
            client.Dispose();
        }

        [Fact]
        public async Task DetectTooLongTextHasMaxLength()
        {
            var client = new WardstoneClient(ValidKey);
            string longText = new string('a', 8_000_001);

            var ex = await Assert.ThrowsAsync<BadRequestException>(() => client.DetectAsync(longText));
            Assert.Equal(8_000_000, ex.MaxLength);
            client.Dispose();
        }

        [Fact]
        public async Task DetectRejectsInvalidScanStrategy()
        {
            var client = new WardstoneClient(ValidKey);
            var request = new DetectRequest("hello") { ScanStrategy = "invalid" };

            var ex = await Assert.ThrowsAsync<BadRequestException>(() => client.DetectAsync(request));
            Assert.Contains("scan_strategy", ex.Message);
            client.Dispose();
        }

        [Fact]
        public async Task DetectAcceptsStringInput()
        {
            var client = new WardstoneClient(ValidKey);
            try
            {
                await client.DetectAsync("Hello world");
                Assert.True(false, "Expected connection error (no server)");
            }
            catch (BadRequestException e)
            {
                Assert.True(false, "String input should be accepted: " + e.Message);
            }
            catch (Exception)
            {
                // Expected: connection error because no server is running
                Assert.True(true);
            }
            finally
            {
                client.Dispose();
            }
        }

        [Fact]
        public async Task DetectAcceptsDetectRequestInput()
        {
            var client = new WardstoneClient(ValidKey);
            try
            {
                await client.DetectAsync(new DetectRequest("Hello world"));
                Assert.True(false, "Expected connection error (no server)");
            }
            catch (BadRequestException e)
            {
                Assert.True(false, "DetectRequest input should be accepted: " + e.Message);
            }
            catch (Exception)
            {
                // Expected: connection error because no server is running
                Assert.True(true);
            }
            finally
            {
                client.Dispose();
            }
        }

        [Fact]
        public async Task DetectRejectsNullRequest()
        {
            var client = new WardstoneClient(ValidKey);
            var ex = await Assert.ThrowsAsync<BadRequestException>(() => client.DetectAsync((DetectRequest)null));
            Assert.Contains("must not be null", ex.Message);
            client.Dispose();
        }

        // -----------------------------------------------------------------------
        // Security: toString excludes API key
        // -----------------------------------------------------------------------

        [Fact]
        public void ToStringExcludesApiKey()
        {
            var client = new WardstoneClient("wst_secret_key_12345678");
            string str = client.ToString();

            Assert.DoesNotContain("wst_secret_key_12345678", str);
            Assert.Contains("wardstone-csharp", str);
            client.Dispose();
        }

        [Fact]
        public void OptionsToStringExcludesApiKey()
        {
            var options = new WardstoneClientOptions
            {
                ApiKey = "wst_secret_key_12345678",
                BaseUrl = "https://wardstone.ai"
            };
            string str = options.ToString();
            Assert.DoesNotContain("wst_secret_key_12345678", str);
        }

        // -----------------------------------------------------------------------
        // Exception hierarchy
        // -----------------------------------------------------------------------

        [Fact]
        public void AuthenticationExceptionHasCorrectFields()
        {
            var ex = new AuthenticationException("test");
            Assert.Equal(401, ex.Status);
            Assert.Equal("authentication_error", ex.Code);
            Assert.Equal("test", ex.Message);
        }

        [Fact]
        public void BadRequestExceptionHasMaxLength()
        {
            var ex = new BadRequestException("too long", "text_too_long", 8000000);
            Assert.Equal(400, ex.Status);
            Assert.Equal("text_too_long", ex.Code);
            Assert.Equal(8000000, ex.MaxLength);
        }

        [Fact]
        public void RateLimitExceptionHasRetryAfter()
        {
            var ex = new RateLimitException("slow down", 30);
            Assert.Equal(429, ex.Status);
            Assert.Equal("rate_limit_error", ex.Code);
            Assert.Equal(30, ex.RetryAfter);
        }

        [Fact]
        public void ConnectionExceptionHasNoStatus()
        {
            var ex = new ConnectionException("failed");
            Assert.Null(ex.Status);
            Assert.Equal("connection_error", ex.Code);
        }

        [Fact]
        public void TimeoutExceptionHasNoStatus()
        {
            var ex = new WardstoneTimeoutException("timed out");
            Assert.Null(ex.Status);
            Assert.Equal("timeout_error", ex.Code);
        }

        [Fact]
        public void AllExceptionsExtendWardstoneException()
        {
            Assert.True(typeof(WardstoneException).IsAssignableFrom(typeof(AuthenticationException)));
            Assert.True(typeof(WardstoneException).IsAssignableFrom(typeof(BadRequestException)));
            Assert.True(typeof(WardstoneException).IsAssignableFrom(typeof(PermissionException)));
            Assert.True(typeof(WardstoneException).IsAssignableFrom(typeof(RateLimitException)));
            Assert.True(typeof(WardstoneException).IsAssignableFrom(typeof(InternalServerException)));
            Assert.True(typeof(WardstoneException).IsAssignableFrom(typeof(ConnectionException)));
            Assert.True(typeof(WardstoneException).IsAssignableFrom(typeof(WardstoneTimeoutException)));
        }

        [Fact]
        public void AllExceptionsAreExceptions()
        {
            Assert.True(typeof(Exception).IsAssignableFrom(typeof(WardstoneException)));
        }

        // -----------------------------------------------------------------------
        // JSON parser: nesting depth limit
        // -----------------------------------------------------------------------

        [Fact]
        public void JsonParserRejectsDeepNesting()
        {
            var sb = new System.Text.StringBuilder();
            for (int i = 0; i < 200; i++) sb.Append("{\"a\":");
            sb.Append("1");
            for (int i = 0; i < 200; i++) sb.Append("}");

            Assert.Throws<ArgumentException>(() => Internal.Json.Parse(sb.ToString()));
        }

        // -----------------------------------------------------------------------
        // JSON parser: number length limit
        // -----------------------------------------------------------------------

        [Fact]
        public void JsonParserRejectsVeryLongNumbers()
        {
            var sb = new System.Text.StringBuilder();
            for (int i = 0; i < 50; i++) sb.Append('1');

            Assert.Throws<ArgumentException>(() => Internal.Json.Parse(sb.ToString()));
        }

        // -----------------------------------------------------------------------
        // JSON parser: leading zeros
        // -----------------------------------------------------------------------

        [Fact]
        public void JsonParserRejectsLeadingZeros()
        {
            Assert.Throws<ArgumentException>(() => Internal.Json.Parse("01"));
        }

        // -----------------------------------------------------------------------
        // JSON parser: surrogate pair validation
        // -----------------------------------------------------------------------

        [Fact]
        public void JsonParserRejectsLoneHighSurrogate()
        {
            Assert.Throws<ArgumentException>(() => Internal.Json.Parse("\"\\uD800\""));
        }

        [Fact]
        public void JsonParserRejectsLoneLowSurrogate()
        {
            Assert.Throws<ArgumentException>(() => Internal.Json.Parse("\"\\uDC00\""));
        }

        [Fact]
        public void JsonParserAcceptsValidSurrogatePair()
        {
            // \uD83D\uDE00 = U+1F600 (grinning face emoji)
            object result = Internal.Json.Parse("\"\\uD83D\\uDE00\"");
            Assert.Equal("\uD83D\uDE00", result);
        }

        // -----------------------------------------------------------------------
        // Security: NonSerialized attribute on apiKey
        // -----------------------------------------------------------------------

        [Fact]
        public void ClientApiKeyFieldsAreNonSerialized()
        {
            // API key is stored XOR-obfuscated in _keyData and _keyMask; both must be [NonSerialized]
            FieldInfo dataField = typeof(WardstoneClient).GetField("_keyData", BindingFlags.NonPublic | BindingFlags.Instance);
            Assert.NotNull(dataField);
            Assert.True(dataField.IsNotSerialized, "_keyData field should be marked [NonSerialized]");

            FieldInfo maskField = typeof(WardstoneClient).GetField("_keyMask", BindingFlags.NonPublic | BindingFlags.Instance);
            Assert.NotNull(maskField);
            Assert.True(maskField.IsNotSerialized, "_keyMask field should be marked [NonSerialized]");
        }

        [Fact]
        public void ClientHasNoPlaintextApiKeyField()
        {
            // Verify there is no field named _apiKey (key should be obfuscated)
            FieldInfo field = typeof(WardstoneClient).GetField("_apiKey", BindingFlags.NonPublic | BindingFlags.Instance);
            Assert.Null(field);
        }

        [Fact]
        public void ClientKeyFieldsAreNotDebuggerBrowsable()
        {
            FieldInfo dataField = typeof(WardstoneClient).GetField("_keyData", BindingFlags.NonPublic | BindingFlags.Instance);
            Assert.NotNull(dataField);
            var dataAttr = dataField.GetCustomAttribute<System.Diagnostics.DebuggerBrowsableAttribute>();
            Assert.NotNull(dataAttr);
            Assert.Equal(System.Diagnostics.DebuggerBrowsableState.Never, dataAttr.State);

            FieldInfo maskField = typeof(WardstoneClient).GetField("_keyMask", BindingFlags.NonPublic | BindingFlags.Instance);
            Assert.NotNull(maskField);
            var maskAttr = maskField.GetCustomAttribute<System.Diagnostics.DebuggerBrowsableAttribute>();
            Assert.NotNull(maskAttr);
            Assert.Equal(System.Diagnostics.DebuggerBrowsableState.Never, maskAttr.State);
        }

        // -----------------------------------------------------------------------
        // Security: ApiKey getter is internal
        // -----------------------------------------------------------------------

        [Fact]
        public void OptionsApiKeyGetterIsNotPublic()
        {
            var prop = typeof(WardstoneClientOptions).GetProperty("ApiKey");
            Assert.NotNull(prop);
            var getter = prop.GetGetMethod(true);
            Assert.NotNull(getter);
            Assert.False(getter.IsPublic, "ApiKey getter should not be public");
        }

        // -----------------------------------------------------------------------
        // Security: serialization prevention
        // -----------------------------------------------------------------------

        [Fact]
        public void ClientSerializationIsBlocked()
        {
            var client = new WardstoneClient(ValidKey);
            // Invoke ISerializable.GetObjectData directly since BinaryFormatter is removed in .NET 10
            var serializable = (System.Runtime.Serialization.ISerializable)client;
            Assert.Throws<System.Runtime.Serialization.SerializationException>(() =>
            {
                serializable.GetObjectData(null, default);
            });
            client.Dispose();
        }

        [Fact]
        public void OptionsSerializationIsBlocked()
        {
            var options = new WardstoneClientOptions { ApiKey = ValidKey };
            var serializable = (System.Runtime.Serialization.ISerializable)options;
            Assert.Throws<System.Runtime.Serialization.SerializationException>(() =>
            {
                serializable.GetObjectData(null, default);
            });
        }

        // -----------------------------------------------------------------------
        // IDisposable
        // -----------------------------------------------------------------------

        [Fact]
        public void ClientImplementsDisposable()
        {
            Assert.True(typeof(IDisposable).IsAssignableFrom(typeof(WardstoneClient)));
        }

        [Fact]
        public void ClientCanBeDisposed()
        {
            var client = new WardstoneClient(ValidKey);
            client.Dispose();
            // Double dispose should not throw
            client.Dispose();
        }

        [Fact]
        public async Task DisposedClientThrowsObjectDisposedException()
        {
            var client = new WardstoneClient(ValidKey);
            client.Dispose();
            await Assert.ThrowsAsync<ObjectDisposedException>(() => client.DetectAsync("test"));
        }

        [Fact]
        public void DisposeClearsKeyMaterial()
        {
            var client = new WardstoneClient(ValidKey);
            client.Dispose();

            // After disposal, _keyData and _keyMask should be null (cleared and released)
            FieldInfo dataField = typeof(WardstoneClient).GetField("_keyData", BindingFlags.NonPublic | BindingFlags.Instance);
            FieldInfo maskField = typeof(WardstoneClient).GetField("_keyMask", BindingFlags.NonPublic | BindingFlags.Instance);
            Assert.Null(dataField.GetValue(client));
            Assert.Null(maskField.GetValue(client));
        }

        // -----------------------------------------------------------------------
        // JSON parser: BOM handling
        // -----------------------------------------------------------------------

        [Fact]
        public void JsonParserStripsBom()
        {
            // UTF-8 BOM (\uFEFF) followed by valid JSON
            object result = Internal.Json.Parse("\uFEFF{\"a\":1}");
            Assert.IsType<System.Collections.Generic.Dictionary<string, object>>(result);
            var dict = (System.Collections.Generic.Dictionary<string, object>)result;
            Assert.Equal(1, dict["a"]);
        }

        [Fact]
        public void JsonParserRejectsBomOnly()
        {
            Assert.Throws<ArgumentException>(() => Internal.Json.Parse("\uFEFF"));
        }
    }
}
