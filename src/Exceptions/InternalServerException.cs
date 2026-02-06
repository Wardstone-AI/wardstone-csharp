using System;
using System.Runtime.Serialization;

namespace Wardstone.Exceptions
{
    /// <summary>
    /// Thrown on HTTP 5xx server errors.
    /// </summary>
    [Serializable]
    public class InternalServerException : WardstoneException
    {
        public InternalServerException(string message)
            : base(message, 500, "internal_server_error")
        {
        }

        /// <summary>Serialization constructor.</summary>
        protected InternalServerException(SerializationInfo info, StreamingContext context)
            : base(info, context)
        {
        }
    }
}
