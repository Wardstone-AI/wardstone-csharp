using System;
using System.Runtime.Serialization;

namespace Wardstone.Exceptions
{
    /// <summary>
    /// Thrown when the API rate limit is exceeded (HTTP 429).
    /// </summary>
    [Serializable]
    public class RateLimitException : WardstoneException
    {
        /// <summary>Suggested retry delay in seconds, or null if not provided.</summary>
        public int? RetryAfter { get; }

        public RateLimitException(string message)
            : this(message, null)
        {
        }

        public RateLimitException(string message, int? retryAfter)
            : base(message, 429, "rate_limit_error")
        {
            RetryAfter = retryAfter;
        }

        /// <summary>Serialization constructor.</summary>
        protected RateLimitException(SerializationInfo info, StreamingContext context)
            : base(info, context)
        {
            if (info.GetBoolean("HasRetryAfter"))
            {
                int ra = info.GetInt32("RetryAfter");
                RetryAfter = (ra > 0 && ra <= 60) ? (int?)ra : null;
            }
        }

        /// <summary>Custom serialization to include RetryAfter.</summary>
        public override void GetObjectData(SerializationInfo info, StreamingContext context)
        {
            base.GetObjectData(info, context);
            info.AddValue("HasRetryAfter", RetryAfter.HasValue);
            if (RetryAfter.HasValue)
            {
                info.AddValue("RetryAfter", RetryAfter.Value);
            }
        }
    }
}
