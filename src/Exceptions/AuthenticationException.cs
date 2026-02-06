using System;
using System.Runtime.Serialization;

namespace Wardstone.Exceptions
{
    /// <summary>
    /// Thrown when the API key is missing or invalid (HTTP 401).
    /// </summary>
    [Serializable]
    public class AuthenticationException : WardstoneException
    {
        public AuthenticationException(string message)
            : base(message, 401, "authentication_error")
        {
        }

        /// <summary>Serialization constructor.</summary>
        protected AuthenticationException(SerializationInfo info, StreamingContext context)
            : base(info, context)
        {
        }
    }
}
