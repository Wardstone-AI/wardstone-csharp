using System;
using System.Net;
using System.Text.RegularExpressions;

namespace Wardstone.Internal
{
    /// <summary>
    /// Input validation, URL validation, and sanitization utilities.
    /// </summary>
    internal static class Validation
    {
        internal const string DefaultBaseUrl = "https://wardstone.ai";
        internal static readonly TimeSpan DefaultTimeout = TimeSpan.FromSeconds(30);
        internal static readonly TimeSpan MaxTimeout = TimeSpan.FromMilliseconds(300_000); // 5 minutes
        internal const int DefaultMaxRetries = 2;
        internal const int MaxMaxRetries = 10;
        internal const long MaxRetryDelayMs = 60_000;
        internal const long MaxCumulativeRetryMs = 120_000; // 2 minute total retry budget
        internal const int MaxResponseBytes = 10 * 1024 * 1024;  // 10 MB
        internal const int MaxErrorBodyBytes = 65_536;            // 64 KB
        internal const int MaxTextLength = 8_000_000;
        internal const int MaxErrorMsgLength = 1000;
        internal const int MinApiKeyLength = 8;

        internal static readonly string[] ValidScanStrategies = { "early-exit", "full-scan", "smart-sample" };

        // Strip ASCII control chars, DEL, and Unicode bidi override characters (prevent log injection)
        private static readonly Regex ControlChars = new Regex(@"[\x00-\x1F\x7F\u200E\u200F\u202A-\u202E\u2066-\u2069]", RegexOptions.Compiled);

        private static readonly Tuple<Regex, string>[] ConnectionErrorMap =
        {
            Tuple.Create(new Regex("(?i)redirect", RegexOptions.Compiled), "Request was redirected. Automatic redirects are disabled for security."),
            Tuple.Create(new Regex("(?i)refused", RegexOptions.Compiled), "Connection refused"),
            Tuple.Create(new Regex("(?i)reset", RegexOptions.Compiled), "Connection reset by peer"),
            Tuple.Create(new Regex(@"(?i)dns|name[\s]?resolution", RegexOptions.Compiled), "DNS lookup failed"),
            Tuple.Create(new Regex(@"(?i)timed?\s{0,20}out", RegexOptions.Compiled), "Connection timed out"),
            Tuple.Create(new Regex("(?i)certificate|cert", RegexOptions.Compiled), "TLS certificate error"),
            Tuple.Create(new Regex("(?i)ssl|tls", RegexOptions.Compiled), "TLS/SSL error"),
            Tuple.Create(new Regex("(?i)eof|closed", RegexOptions.Compiled), "Connection closed unexpectedly"),
        };

        /// <summary>Validate and normalize a base URL.</summary>
        internal static string ValidateBaseUrl(string url)
        {
            string trimmed = url.TrimEnd('/');
            Uri uri;
            try
            {
                uri = new Uri(trimmed);
            }
            catch (Exception)
            {
                string safeUrl = url.Length > 200 ? url.Substring(0, 200) + "..." : url;
                safeUrl = ControlChars.Replace(safeUrl, "");
                throw new Exceptions.WardstoneException("Invalid baseUrl: \"" + safeUrl + "\" is not a valid URL.");
            }

            string scheme = uri.Scheme;
            if (scheme != "https" && scheme != "http")
            {
                throw new Exceptions.WardstoneException(
                    "Invalid baseUrl protocol \"" + scheme + "\". Only https: and http: are supported."
                );
            }

            if (!string.IsNullOrEmpty(uri.UserInfo))
            {
                throw new Exceptions.WardstoneException("baseUrl must not contain credentials (user:pass@host).");
            }

            if (scheme == "http")
            {
                // Use IPAddress.IsLoopback to catch all loopback representations
                // (127.0.0.1, ::1, ::ffff:127.0.0.1, [0:0:0:0:0:0:0:1], etc.)
                // Hostname "localhost" is intentionally NOT resolved to prevent DNS rebinding.
                string host = uri.Host;
                IPAddress addr;
                bool isLoopback = IPAddress.TryParse(host, out addr) && IPAddress.IsLoopback(addr);
                if (!isLoopback)
                {
                    throw new Exceptions.WardstoneException(
                        "Insecure baseUrl: HTTP is only allowed for localhost. Use HTTPS for remote hosts."
                    );
                }
            }

            if (!string.IsNullOrEmpty(uri.Query) && uri.Query != "?")
            {
                throw new Exceptions.WardstoneException("baseUrl must not contain query parameters.");
            }

            string fragment = uri.Fragment;
            if (!string.IsNullOrEmpty(fragment) && fragment != "#")
            {
                throw new Exceptions.WardstoneException("baseUrl must not contain fragments.");
            }

            if (uri.AbsolutePath.Contains(".."))
            {
                throw new Exceptions.WardstoneException("baseUrl must not contain path traversal sequences.");
            }

            return trimmed;
        }

        /// <summary>Sanitize an error message: truncate and strip control chars.</summary>
        internal static string SanitizeMessage(string msg)
        {
            string truncated = msg.Length > MaxErrorMsgLength
                ? msg.Substring(0, MaxErrorMsgLength) + "..."
                : msg;
            return ControlChars.Replace(truncated, "");
        }

        /// <summary>Map a connection error message to a safe, generic message.</summary>
        internal static string SanitizeConnectionError(string msg)
        {
            // Truncate before regex matching to bound processing time
            if (msg.Length > 500) msg = msg.Substring(0, 500);
            foreach (var entry in ConnectionErrorMap)
            {
                if (entry.Item1.IsMatch(msg))
                {
                    return entry.Item2;
                }
            }
            return "Connection failed";
        }

        /// <summary>Check if a scan strategy is valid.</summary>
        internal static bool IsValidScanStrategy(string strategy)
        {
            foreach (string valid in ValidScanStrategies)
            {
                if (valid == strategy) return true;
            }
            return false;
        }
    }
}
