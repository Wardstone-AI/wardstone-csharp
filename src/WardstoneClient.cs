using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Runtime.Serialization;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Wardstone.Exceptions;
using Wardstone.Internal;
using Wardstone.Models;

namespace Wardstone
{
    /// <summary>
    /// Client for the Wardstone LLM security API.
    ///
    /// This client is designed to be created once and reused across requests.
    /// It manages an internal HTTP connection pool. Creating many short-lived
    /// instances is not recommended. This class must not be serialized.
    ///
    /// <code>
    /// var client = new WardstoneClient("YOUR_API_KEY");
    /// var result = await client.DetectAsync(userInput);
    /// </code>
    /// </summary>
    // [Serializable] is required so that ISerializable.GetObjectData is invoked by BinaryFormatter.
    // Without it, BinaryFormatter would throw a generic error. With it, our custom GetObjectData
    // throws SerializationException with a clear message about API key protection.
    [Serializable]
    [DebuggerDisplay("WardstoneClient (baseUrl={_baseUrl})")]
    public sealed class WardstoneClient : IDisposable, ISerializable
    {
        // API key stored XOR-obfuscated to prevent casual reflection/memory dump access.
        // The raw key is never stored as a plain string field.
        [NonSerialized]
        [DebuggerBrowsable(DebuggerBrowsableState.Never)]
        private byte[] _keyData;
        [NonSerialized]
        [DebuggerBrowsable(DebuggerBrowsableState.Never)]
        private byte[] _keyMask;
        private readonly string _baseUrl;
        private readonly TimeSpan _timeout;
        private readonly int _maxRetries;
        [NonSerialized]
        private readonly HttpClient _httpClient;
        // _threadRandom is only used for non-security-critical retry jitter.
        // It must NOT be used for token generation, nonces, or any security-sensitive randomness.
        [NonSerialized]
        private readonly ThreadLocal<Random> _threadRandom;
        private int _disposed; // 0 = not disposed, 1 = disposed (for Interlocked)

        private static int CryptoSeed()
        {
            var buf = new byte[4];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(buf);
            }
            return BitConverter.ToInt32(buf, 0);
        }

        /// <summary>Retrieve the API key by XOR-unmasking the stored bytes.</summary>
        [MethodImpl(MethodImplOptions.NoInlining)]
        private string GetApiKey()
        {
            // Capture local references to prevent race with Dispose() nulling the fields
            byte[] data = _keyData;
            byte[] mask = _keyMask;
            if (data == null || mask == null)
            {
                throw new ObjectDisposedException(nameof(WardstoneClient));
            }
            var raw = new byte[data.Length];
            for (int i = 0; i < raw.Length; i++)
            {
                raw[i] = (byte)(data[i] ^ mask[i % mask.Length]);
            }
            // Note: the returned string is immutable and will persist until GC'd (inherent .NET limitation).
            // We clear the intermediate byte array to minimize the plaintext exposure window.
            string result = Encoding.UTF8.GetString(raw);
            Array.Clear(raw, 0, raw.Length);
            return result;
        }

        /// <summary>Store the API key XOR-masked with a random pad.</summary>
        private static void MaskKey(string key, out byte[] data, out byte[] mask)
        {
            byte[] keyBytes = Encoding.UTF8.GetBytes(key);
            mask = new byte[32];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(mask);
            }
            data = new byte[keyBytes.Length];
            for (int i = 0; i < keyBytes.Length; i++)
            {
                data[i] = (byte)(keyBytes[i] ^ mask[i % mask.Length]);
            }
            // Clear the plaintext bytes
            Array.Clear(keyBytes, 0, keyBytes.Length);
        }

        /// <summary>
        /// Create a client with the given API key and default settings.
        /// </summary>
        /// <param name="apiKey">Your Wardstone API key.</param>
        public WardstoneClient(string apiKey)
            : this(new WardstoneClientOptions { ApiKey = apiKey })
        {
        }

        /// <summary>
        /// Create a client with full configuration.
        /// If no options are provided, the API key is read from the WARDSTONE_API_KEY environment variable.
        /// </summary>
        /// <param name="options">Client configuration options.</param>
        public WardstoneClient(WardstoneClientOptions options = null)
        {
            if (options == null)
            {
                options = new WardstoneClientOptions();
            }

            // Resolve API key
            string raw = options.ApiKey;
            if (string.IsNullOrEmpty(raw))
            {
                raw = Environment.GetEnvironmentVariable("WARDSTONE_API_KEY");
            }
            if (string.IsNullOrWhiteSpace(raw))
            {
                throw new AuthenticationException(
                    "API key is required. Pass it via the ApiKey option or set the WARDSTONE_API_KEY environment variable."
                );
            }
            string key = raw.Trim();
            if (key.Length < Validation.MinApiKeyLength)
            {
                throw new AuthenticationException(
                    "API key is too short (minimum " + Validation.MinApiKeyLength + " characters). "
                    + "Check that you are using a valid Wardstone API key."
                );
            }
            // Reject control characters to prevent HTTP header injection
            for (int i = 0; i < key.Length; i++)
            {
                char c = key[i];
                if (c < 0x20 || c == 0x7F)
                {
                    throw new AuthenticationException(
                        "API key contains invalid characters. Keys must contain only printable ASCII characters."
                    );
                }
            }
            MaskKey(key, out _keyData, out _keyMask);

            // Initialize thread-safe random with cryptographic seed
            _threadRandom = new ThreadLocal<Random>(() => new Random(CryptoSeed()));

            // Clear key reference from options to reduce exposure window
            options.ApiKey = null;

            // Remaining initialization is wrapped in try/catch to dispose already-created
            // resources (_threadRandom) if validation fails.
            try
            {
                // Resolve base URL
                string url = options.BaseUrl;
                if (string.IsNullOrEmpty(url))
                {
                    url = Validation.DefaultBaseUrl;
                }
                _baseUrl = Validation.ValidateBaseUrl(url);

                // Resolve timeout
                TimeSpan? t = options.Timeout;
                if (!t.HasValue)
                {
                    t = Validation.DefaultTimeout;
                }
                if (t.Value <= TimeSpan.Zero)
                {
                    throw new WardstoneException("timeout must be a positive duration.");
                }
                if (t.Value > Validation.MaxTimeout)
                {
                    throw new WardstoneException(
                        "timeout must not exceed " + (int)Validation.MaxTimeout.TotalMilliseconds + "ms."
                    );
                }
                _timeout = t.Value;

                // Resolve max retries
                int mr = options.MaxRetries ?? Validation.DefaultMaxRetries;
                if (mr < 0 || mr > Validation.MaxMaxRetries)
                {
                    throw new WardstoneException(
                        "maxRetries must be an integer between 0 and " + Validation.MaxMaxRetries + "."
                    );
                }
                _maxRetries = mr;

                // Create HTTP client with redirects disabled and TLS 1.2+ enforced
                // TLS 1.3 = (SslProtocols)12288; use numeric value for netstandard2.0 compat
                var handler = new HttpClientHandler
                {
                    AllowAutoRedirect = false,
                    SslProtocols = System.Security.Authentication.SslProtocols.Tls12 | (System.Security.Authentication.SslProtocols)12288
                };

                _httpClient = new HttpClient(handler)
                {
                    Timeout = _timeout
                };
            }
            catch
            {
                // Clean up already-created disposable resources on constructor failure
                _threadRandom?.Dispose();
                throw;
            }
        }

        /// <summary>
        /// Analyze text for security threats.
        /// </summary>
        /// <param name="text">The text to analyze.</param>
        /// <param name="cancellationToken">Optional cancellation token.</param>
        /// <returns>Detection result with risk bands, subcategories, and processing info.</returns>
        public Task<DetectResult> DetectAsync(string text, CancellationToken cancellationToken = default)
        {
            return DetectAsync(new DetectRequest(text), cancellationToken);
        }

        /// <summary>
        /// Analyze text for security threats with full request options.
        /// </summary>
        /// <param name="request">The detection request.</param>
        /// <param name="cancellationToken">Optional cancellation token.</param>
        /// <returns>Detection result with risk bands, subcategories, and processing info.</returns>
        public async Task<DetectResult> DetectAsync(DetectRequest request, CancellationToken cancellationToken = default)
        {
            ThrowIfDisposed();

            if (request == null)
            {
                throw new BadRequestException("request must not be null.", "invalid_input", null);
            }
            // Snapshot mutable properties once to prevent TOCTOU races if the request
            // is concurrently modified by another thread between validation and serialization.
            string text = request.Text;
            string scanStrategy = request.ScanStrategy;
            bool? includeRawScores = request.IncludeRawScores;

            if (string.IsNullOrEmpty(text))
            {
                throw new BadRequestException("text must be a non-empty string.", "invalid_input", null);
            }
            if (text.Length > Validation.MaxTextLength)
            {
                throw new BadRequestException(
                    "text exceeds maximum length of " + Validation.MaxTextLength + " characters.",
                    "text_too_long", Validation.MaxTextLength
                );
            }
            if (scanStrategy != null && (scanStrategy.Length > 50 || !Validation.IsValidScanStrategy(scanStrategy)))
            {
                throw new BadRequestException(
                    "Invalid scan_strategy. Must be one of: " + string.Join(", ", Validation.ValidScanStrategies) + ".",
                    "invalid_input", null
                );
            }

            // Build request body from known properties only (prevent property injection)
            var body = new Dictionary<string, object>();
            body["text"] = text;
            if (scanStrategy != null)
            {
                body["scan_strategy"] = scanStrategy;
            }
            if (includeRawScores.HasValue)
            {
                body["include_raw_scores"] = includeRawScores.Value;
            }

            var resp = await DoRequestAsync("/api/detect", body, cancellationToken).ConfigureAwait(false);
            try
            {
                var data = ValidateDetectResponse(resp.Body);
                var rateLimit = ParseRateLimit(resp.Headers);
                return BuildResult(data, rateLimit);
            }
            finally
            {
                resp.Response.Dispose();
            }
        }

        /// <summary>Identity-based equality; prevents key material from being used in comparisons.</summary>
        public override bool Equals(object obj) { return ReferenceEquals(this, obj); }

        /// <summary>Identity-based hash code; prevents key material from being used in hash computation.</summary>
        public override int GetHashCode() { return System.Runtime.CompilerServices.RuntimeHelpers.GetHashCode(this); }

        /// <summary>Prevents API key from appearing in ToString() output.</summary>
        public override string ToString()
        {
            return "WardstoneClient{sdk='wardstone-csharp'"
                + ", baseUrl='" + _baseUrl + "'"
                + ", timeout=" + (int)_timeout.TotalMilliseconds + "ms"
                + ", maxRetries=" + _maxRetries + "}";
        }

        /// <summary>Prevents serialization which could write the API key to disk/network.</summary>
        void ISerializable.GetObjectData(SerializationInfo info, StreamingContext context)
        {
            throw new SerializationException("WardstoneClient cannot be serialized (API key protection).");
        }

        /// <summary>Prevents deserialization.</summary>
        private WardstoneClient(SerializationInfo info, StreamingContext context)
        {
            throw new SerializationException("WardstoneClient cannot be deserialized (API key protection).");
        }

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _disposed, 1) == 0)
            {
                // Clear key material from memory before releasing references
                if (_keyData != null) Array.Clear(_keyData, 0, _keyData.Length);
                if (_keyMask != null) Array.Clear(_keyMask, 0, _keyMask.Length);
                _keyData = null;
                _keyMask = null;
                _httpClient?.Dispose();
                _threadRandom?.Dispose();
            }
        }

        private void ThrowIfDisposed()
        {
            if (Volatile.Read(ref _disposed) != 0)
            {
                throw new ObjectDisposedException(nameof(WardstoneClient));
            }
        }

        // -------------------------------------------------------------------------
        // Internal: HTTP request with retry
        // -------------------------------------------------------------------------

        private sealed class ResponseData
        {
            public Dictionary<string, object> Body { get; }
            public HttpResponseMessage Response { get; }
            public System.Net.Http.Headers.HttpResponseHeaders Headers { get; }

            public ResponseData(Dictionary<string, object> body, HttpResponseMessage response)
            {
                Body = body;
                Response = response;
                Headers = response.Headers;
            }
        }

        private async Task<ResponseData> DoRequestAsync(string path, Dictionary<string, object> body, CancellationToken cancellationToken)
        {
            string url = _baseUrl + path;
            string jsonBody = Json.Stringify(body);
            long cumulativeDelayMs = 0;

            for (int attempt = 0; attempt <= _maxRetries; attempt++)
            {
                HttpResponseMessage response;
                try
                {
                    using (var httpRequest = new HttpRequestMessage(HttpMethod.Post, url))
                    {
                        httpRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", GetApiKey());
                        httpRequest.Headers.UserAgent.ParseAdd("wardstone-csharp/" + Version.Value);
                        httpRequest.Content = new StringContent(jsonBody, Encoding.UTF8, "application/json");

                        response = await _httpClient.SendAsync(httpRequest, HttpCompletionOption.ResponseHeadersRead, cancellationToken).ConfigureAwait(false);

                        // Clear the Authorization header to break the reference to the API key string sooner
                        httpRequest.Headers.Authorization = null;
                    }
                }
                catch (TaskCanceledException) when (!cancellationToken.IsCancellationRequested)
                {
                    throw new WardstoneTimeoutException("Request timed out after " + (int)_timeout.TotalMilliseconds + "ms");
                }
                catch (TaskCanceledException)
                {
                    throw new ConnectionException("Request was cancelled");
                }
                catch (ObjectDisposedException)
                {
                    // Re-throw with consistent type if client was disposed during request
                    throw new ObjectDisposedException(nameof(WardstoneClient));
                }
                catch (HttpRequestException ex)
                {
                    string msg = ex.Message ?? "";
                    throw new ConnectionException(Validation.SanitizeConnectionError(msg));
                }

                int status = (int)response.StatusCode;

                // Check for redirect status codes (3xx)
                if (status >= 300 && status < 400)
                {
                    response.Dispose();
                    throw new ConnectionException(
                        "Request was redirected. Automatic redirects are disabled for security."
                    );
                }

                if (status >= 200 && status < 300)
                {
                    // Validate Content-Type
                    string contentType = response.Content?.Headers?.ContentType?.MediaType ?? "";
                    if (!contentType.Equals("application/json", StringComparison.OrdinalIgnoreCase))
                    {
                        response.Dispose();
                        string safeCt = contentType.Length > 200 ? contentType.Substring(0, 200) + "..." : contentType;
                        throw new WardstoneException(
                            "Unexpected Content-Type: \"" + safeCt + "\". "
                            + "Expected application/json. This may indicate a proxy, CDN, "
                            + "or captive portal intercepting the request."
                        );
                    }

                    // Content-Length pre-check before reading body
                    long? contentLength = response.Content?.Headers?.ContentLength;
                    if (contentLength.HasValue && contentLength.Value > Validation.MaxResponseBytes)
                    {
                        response.Dispose();
                        throw new WardstoneException(
                            "Response body too large (>" + Validation.MaxResponseBytes + " bytes). Maximum: " + Validation.MaxResponseBytes + " bytes."
                        );
                    }

                    // Read response body with streaming size limit
                    byte[] responseBody;
                    try
                    {
                        responseBody = await ReadBoundedAsync(response, Validation.MaxResponseBytes, cancellationToken).ConfigureAwait(false);
                    }
                    catch
                    {
                        response.Dispose();
                        throw;
                    }

                    string responseText;
                    try
                    {
                        responseText = Encoding.UTF8.GetString(responseBody);
                    }
                    catch (Exception)
                    {
                        response.Dispose();
                        throw new WardstoneException("Invalid API response: unable to decode UTF-8.");
                    }

                    object parsed;
                    try
                    {
                        parsed = Json.Parse(responseText);
                    }
                    catch (Exception)
                    {
                        response.Dispose();
                        throw new WardstoneException("Invalid API response: expected JSON.");
                    }

                    if (!(parsed is Dictionary<string, object> dict))
                    {
                        response.Dispose();
                        throw new WardstoneException("Invalid API response: expected a JSON object.");
                    }

                    return new ResponseData(dict, response);
                }

                // Read error body with streaming size limit; if too large, proceed with empty body
                byte[] errorBody;
                long? errorContentLength = response.Content?.Headers?.ContentLength;
                if (errorContentLength.HasValue && errorContentLength.Value > Validation.MaxErrorBodyBytes)
                {
                    errorBody = Array.Empty<byte>();
                }
                else
                {
                    try
                    {
                        errorBody = await ReadBoundedAsync(response, Validation.MaxErrorBodyBytes, cancellationToken).ConfigureAwait(false);
                    }
                    catch
                    {
                        errorBody = Array.Empty<byte>();
                    }
                }

                // Retryable: 429 and 5xx
                bool retryable = status == 429 || status >= 500;
                if (retryable && attempt < _maxRetries)
                {
                    long delay = GetRetryDelay(response, attempt);

                    // Cumulative retry time budget (120s max, matching Java SDK)
                    cumulativeDelayMs += delay;
                    if (cumulativeDelayMs > Validation.MaxCumulativeRetryMs)
                    {
                        ThrowForStatus(status, response, errorBody);
                    }

                    response.Dispose();
                    await Task.Delay((int)delay, cancellationToken).ConfigureAwait(false);
                    continue;
                }

                // Non-retryable or exhausted retries: dispose before throwing
                try
                {
                    ThrowForStatus(status, response, errorBody);
                }
                finally
                {
                    response.Dispose();
                }
            }

            throw new WardstoneException("Unexpected retry exhaustion");
        }

        private long GetRetryDelay(HttpResponseMessage response, int attempt)
        {
            // Check Retry-After header (numeric seconds only; date-format is intentionally
            // ignored and falls through to exponential backoff, which is safe behavior)
            IEnumerable<string> retryAfterValues;
            if (response.Headers.TryGetValues("Retry-After", out retryAfterValues))
            {
                string retryAfter = retryAfterValues.FirstOrDefault();
                if (retryAfter != null)
                {
                    double seconds;
                    if (double.TryParse(retryAfter, NumberStyles.Float, CultureInfo.InvariantCulture, out seconds))
                    {
                        if (seconds > 0 && !double.IsInfinity(seconds) && !double.IsNaN(seconds))
                        {
                            long delayMs = Math.Max(1L, (long)(seconds * 1000));
                            return Math.Min(delayMs, Validation.MaxRetryDelayMs);
                        }
                    }
                }
            }
            // Exponential backoff with jitter: 500ms, 1s, 2s, ... (randomized 50-100%)
            long baseDelay = Math.Min(500L * (1L << attempt), 8000L);
            double jitter = _threadRandom.Value.NextDouble();
            return (long)(baseDelay * (0.5 + jitter * 0.5));
        }

        private static void ThrowForStatus(int status, HttpResponseMessage response, byte[] body)
        {
            string rawMessage = "Request failed";
            string errorCode = null;
            int? maxLength = null;

            try
            {
                string text = Encoding.UTF8.GetString(body);
                object parsed = Json.Parse(text);
                if (parsed is Dictionary<string, object> map)
                {
                    object msg;
                    if (map.TryGetValue("message", out msg) && msg is string msgStr)
                    {
                        if (msgStr.Length > Validation.MaxErrorMsgLength)
                            msgStr = msgStr.Substring(0, Validation.MaxErrorMsgLength);
                        rawMessage = msgStr;
                    }
                    object err;
                    if (map.TryGetValue("error", out err) && err is string errStr)
                    {
                        // Truncate and sanitize errorCode from server response
                        if (errStr.Length > 200) errStr = errStr.Substring(0, 200);
                        errorCode = Validation.SanitizeMessage(errStr);
                    }
                    object ml;
                    if (map.TryGetValue("maxLength", out ml) && ml is int mlInt && mlInt > 0 && mlInt <= Validation.MaxTextLength)
                    {
                        maxLength = mlInt;
                    }
                }
            }
            catch
            {
                // Ignore parse errors for error bodies
            }

            string message = Validation.SanitizeMessage(rawMessage);

            switch (status)
            {
                case 400:
                    throw new BadRequestException(message, errorCode, maxLength);
                case 401:
                    throw new AuthenticationException(message);
                case 403:
                    throw new PermissionException(message);
                case 429:
                    int? retryAfterSec = null;
                    IEnumerable<string> raValues;
                    if (response.Headers.TryGetValues("Retry-After", out raValues))
                    {
                        string ra = raValues.FirstOrDefault();
                        if (ra != null)
                        {
                            int val;
                            if (int.TryParse(ra, out val) && val > 0)
                            {
                                // Cap at MaxRetryDelayMs (converted to seconds)
                                int maxSec = (int)(Validation.MaxRetryDelayMs / 1000);
                                retryAfterSec = Math.Min(val, maxSec);
                            }
                        }
                    }
                    throw new RateLimitException(message, retryAfterSec);
                default:
                    if (status >= 500)
                    {
                        throw new InternalServerException(message);
                    }
                    throw new WardstoneException(message, status, errorCode);
            }
        }

        // -------------------------------------------------------------------------
        // Internal: response validation
        // -------------------------------------------------------------------------

        private static Dictionary<string, object> ValidateDetectResponse(Dictionary<string, object> data)
        {
            // Validate flagged
            object flagged;
            if (!data.TryGetValue("flagged", out flagged) || !(flagged is bool))
            {
                throw new WardstoneException("Invalid API response: missing or invalid 'flagged' field.");
            }

            // Validate risk_bands
            object bandsObj;
            if (!data.TryGetValue("risk_bands", out bandsObj) || !(bandsObj is Dictionary<string, object> bands))
            {
                throw new WardstoneException("Invalid API response: missing or invalid 'risk_bands' field.");
            }
            foreach (string key in new[] { "content_violation", "prompt_attack", "data_leakage", "unknown_links" })
            {
                object band;
                if (!bands.TryGetValue(key, out band) || !(band is Dictionary<string, object> bandDict))
                {
                    throw new WardstoneException("Invalid API response: missing risk_bands." + key + ".");
                }
                object level;
                if (!bandDict.TryGetValue("level", out level) || !(level is string))
                {
                    throw new WardstoneException("Invalid API response: missing risk_bands." + key + ".level.");
                }
            }

            // Validate subcategories
            object subsObj;
            if (!data.TryGetValue("subcategories", out subsObj) || !(subsObj is Dictionary<string, object> subs))
            {
                throw new WardstoneException("Invalid API response: missing or invalid 'subcategories' field.");
            }
            foreach (string key in new[] { "content_violation", "data_leakage" })
            {
                object sub;
                if (!subs.TryGetValue(key, out sub) || !(sub is Dictionary<string, object> subDict))
                {
                    throw new WardstoneException("Invalid API response: missing subcategories." + key + ".");
                }
                object triggered;
                if (!subDict.TryGetValue("triggered", out triggered) || !(triggered is List<object> triggeredList))
                {
                    throw new WardstoneException(
                        "Invalid API response: subcategories." + key + ".triggered must be an array."
                    );
                }
                foreach (object item in triggeredList)
                {
                    if (!(item is string))
                    {
                        throw new WardstoneException(
                            "Invalid API response: subcategories." + key + ".triggered must contain only strings."
                        );
                    }
                }
            }

            // Validate unknown_links
            object linksObj;
            if (!data.TryGetValue("unknown_links", out linksObj) || !(linksObj is Dictionary<string, object> links))
            {
                throw new WardstoneException("Invalid API response: missing or invalid 'unknown_links' field.");
            }
            object linksFlagged;
            if (!links.TryGetValue("flagged", out linksFlagged) || !(linksFlagged is bool))
            {
                throw new WardstoneException("Invalid API response: missing unknown_links.flagged.");
            }

            // Validate processing
            object procObj;
            if (!data.TryGetValue("processing", out procObj) || !(procObj is Dictionary<string, object> proc))
            {
                throw new WardstoneException("Invalid API response: missing or invalid 'processing' field.");
            }
            object inferenceMs;
            if (!proc.TryGetValue("inference_ms", out inferenceMs) || !(inferenceMs is int || inferenceMs is long || inferenceMs is double))
            {
                throw new WardstoneException("Invalid API response: missing processing.inference_ms.");
            }

            return data;
        }

        private static DetectResult BuildResult(Dictionary<string, object> data, RateLimitInfo rateLimit)
        {
            bool flagged = (bool)data["flagged"];

            // Risk bands
            var bandsMap = (Dictionary<string, object>)data["risk_bands"];
            var riskBands = new RiskBands(
                new RiskBand((string)((Dictionary<string, object>)bandsMap["content_violation"])["level"]),
                new RiskBand((string)((Dictionary<string, object>)bandsMap["prompt_attack"])["level"]),
                new RiskBand((string)((Dictionary<string, object>)bandsMap["data_leakage"])["level"]),
                new RiskBand((string)((Dictionary<string, object>)bandsMap["unknown_links"])["level"])
            );

            // Primary category
            object primaryCat;
            string primaryCategory = null;
            if (data.TryGetValue("primary_category", out primaryCat) && primaryCat is string pc)
            {
                primaryCategory = pc;
            }

            // Subcategories
            var subsMap = (Dictionary<string, object>)data["subcategories"];
            var cvSub = (Dictionary<string, object>)subsMap["content_violation"];
            var dlSub = (Dictionary<string, object>)subsMap["data_leakage"];
            var subcategories = new Subcategories(
                new SubcategoryDetail(ToStringList((List<object>)cvSub["triggered"])),
                new SubcategoryDetail(ToStringList((List<object>)dlSub["triggered"]))
            );

            // Unknown links
            var linksMap = (Dictionary<string, object>)data["unknown_links"];
            var unknownLinks = new Models.UnknownLinks(
                (bool)linksMap["flagged"],
                ToInt(linksMap, "unknown_count"),
                ToInt(linksMap, "known_count"),
                ToInt(linksMap, "total_urls"),
                linksMap.ContainsKey("unknown_domains") && linksMap["unknown_domains"] is List<object>
                    ? ToStringList((List<object>)linksMap["unknown_domains"])
                    : new List<string>().AsReadOnly()
            );

            // Processing
            var procMap = (Dictionary<string, object>)data["processing"];
            object scanStrategyObj;
            string scanStrategy = "early-exit";
            if (procMap.TryGetValue("scan_strategy", out scanStrategyObj) && scanStrategyObj is string ss)
            {
                scanStrategy = ss;
            }
            int? chunksScanned = null;
            object cs;
            if (procMap.TryGetValue("chunks_scanned", out cs) && (cs is int || cs is long || cs is double))
            {
                chunksScanned = SafeToInt(cs);
            }
            int? totalChunks = null;
            object tc;
            if (procMap.TryGetValue("total_chunks", out tc) && (tc is int || tc is long || tc is double))
            {
                totalChunks = SafeToInt(tc);
            }
            var processing = new Processing(
                ToDouble(procMap["inference_ms"]),
                ToInt(procMap, "input_length"),
                scanStrategy,
                chunksScanned,
                totalChunks
            );

            // Raw scores (optional)
            RawScores rawScores = null;
            object rawObj;
            if (data.TryGetValue("raw_scores", out rawObj) && rawObj is Dictionary<string, object> rawMap)
            {
                var cats = ToDoubleMap(rawMap, "categories");
                Dictionary<string, object> rawSubs = null;
                object rawSubsObj;
                if (rawMap.TryGetValue("subcategories", out rawSubsObj) && rawSubsObj is Dictionary<string, object> rs)
                {
                    rawSubs = rs;
                }

                IReadOnlyDictionary<string, double> cvScores = null;
                IReadOnlyDictionary<string, double> dlScores = null;
                if (rawSubs != null)
                {
                    object cvObj;
                    if (rawSubs.TryGetValue("content_violation", out cvObj) && cvObj is Dictionary<string, object>)
                    {
                        cvScores = ToDoubleMap(rawSubs, "content_violation");
                    }
                    object dlObj;
                    if (rawSubs.TryGetValue("data_leakage", out dlObj) && dlObj is Dictionary<string, object>)
                    {
                        dlScores = ToDoubleMap(rawSubs, "data_leakage");
                    }
                }

                rawScores = new RawScores(cats, cvScores, dlScores);
            }

            return new DetectResult(flagged, riskBands, primaryCategory, subcategories,
                unknownLinks, processing, rawScores, rateLimit);
        }

        private static RateLimitInfo ParseRateLimit(System.Net.Http.Headers.HttpResponseHeaders headers)
        {
            return new RateLimitInfo(
                ParseIntHeader(headers, "X-RateLimit-Limit"),
                ParseIntHeader(headers, "X-RateLimit-Remaining"),
                ParseIntHeader(headers, "X-RateLimit-Reset")
            );
        }

        private static int ParseIntHeader(System.Net.Http.Headers.HttpResponseHeaders headers, string name)
        {
            IEnumerable<string> values;
            if (headers.TryGetValues(name, out values))
            {
                string val = values.FirstOrDefault();
                if (val != null)
                {
                    int result;
                    if (int.TryParse(val, out result))
                    {
                        return result;
                    }
                }
            }
            return 0;
        }

        // -------------------------------------------------------------------------
        // Internal: streaming body reader
        // -------------------------------------------------------------------------

        private static async Task<byte[]> ReadBoundedAsync(HttpResponseMessage response, int maxBytes, CancellationToken cancellationToken)
        {
            // Pre-allocate MemoryStream capacity from Content-Length if known, to reduce reallocations
            long? cl = response.Content?.Headers?.ContentLength;
            int initialCapacity = (cl.HasValue && cl.Value > 0 && cl.Value <= maxBytes) ? (int)cl.Value : 0;

            using (var stream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false))
            using (var ms = initialCapacity > 0 ? new MemoryStream(initialCapacity) : new MemoryStream())
            {
                var buf = new byte[8192];
                long total = 0;
                int n;
                while ((n = await stream.ReadAsync(buf, 0, buf.Length, cancellationToken).ConfigureAwait(false)) > 0)
                {
                    total += n;
                    if (total > maxBytes)
                    {
                        throw new WardstoneException(
                            "Response body too large (>" + maxBytes + " bytes). Maximum: " + maxBytes + " bytes."
                        );
                    }
                    ms.Write(buf, 0, n);
                }
                return ms.ToArray();
            }
        }

        // -------------------------------------------------------------------------
        // Internal: type conversion helpers
        // -------------------------------------------------------------------------

        private static IReadOnlyList<string> ToStringList(List<object> list)
        {
            var result = new List<string>(list.Count);
            foreach (object item in list)
            {
                result.Add(item is string s ? s : (item ?? "").ToString());
            }
            return result.AsReadOnly();
        }

        private static int ToInt(Dictionary<string, object> map, string key)
        {
            object value;
            if (map.TryGetValue(key, out value))
            {
                return SafeToInt(value);
            }
            return 0;
        }

        private static int SafeToInt(object value)
        {
            if (value is int i) return i;
            if (value is long l)
            {
                if (l > int.MaxValue) return int.MaxValue;
                if (l < int.MinValue) return int.MinValue;
                return (int)l;
            }
            if (value is double d)
            {
                if (d > int.MaxValue) return int.MaxValue;
                if (d < int.MinValue) return int.MinValue;
                if (double.IsNaN(d)) return 0;
                return (int)d;
            }
            return 0;
        }

        private static double ToDouble(object value)
        {
            if (value is double d) return d;
            if (value is int i) return i;
            if (value is long l) return l;
            return 0;
        }

        private static IReadOnlyDictionary<string, double> ToDoubleMap(Dictionary<string, object> parent, string key)
        {
            object obj;
            if (!parent.TryGetValue(key, out obj) || !(obj is Dictionary<string, object> map))
            {
                return new ReadOnlyDictionary<string, double>(new Dictionary<string, double>());
            }
            var result = new Dictionary<string, double>();
            foreach (var entry in map)
            {
                if (entry.Value is int i)
                {
                    result[entry.Key] = i;
                }
                else if (entry.Value is long l)
                {
                    result[entry.Key] = l;
                }
                else if (entry.Value is double d)
                {
                    result[entry.Key] = d;
                }
            }
            return new ReadOnlyDictionary<string, double>(result);
        }
    }
}
