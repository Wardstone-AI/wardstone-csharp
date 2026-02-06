using System;
using System.Runtime.Serialization;

namespace Wardstone.Exceptions
{
    /// <summary>
    /// Thrown when a request times out.
    /// Named WardstoneTimeoutException to avoid conflict with System.TimeoutException.
    /// </summary>
    [Serializable]
    public class WardstoneTimeoutException : WardstoneException
    {
        public WardstoneTimeoutException(string message)
            : base(message, null, "timeout_error")
        {
        }

        /// <summary>Serialization constructor.</summary>
        protected WardstoneTimeoutException(SerializationInfo info, StreamingContext context)
            : base(info, context)
        {
        }
    }
}
