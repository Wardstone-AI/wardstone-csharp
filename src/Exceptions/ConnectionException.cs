using System;
using System.Runtime.Serialization;

namespace Wardstone.Exceptions
{
    /// <summary>
    /// Thrown when a network connection failure occurs.
    /// </summary>
    [Serializable]
    public class ConnectionException : WardstoneException
    {
        public ConnectionException(string message)
            : base(message, null, "connection_error")
        {
        }

        /// <summary>Serialization constructor.</summary>
        protected ConnectionException(SerializationInfo info, StreamingContext context)
            : base(info, context)
        {
        }
    }
}
