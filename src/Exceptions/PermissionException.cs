using System;
using System.Runtime.Serialization;

namespace Wardstone.Exceptions
{
    /// <summary>
    /// Thrown when the API key lacks required permissions (HTTP 403).
    /// </summary>
    [Serializable]
    public class PermissionException : WardstoneException
    {
        public PermissionException(string message)
            : base(message, 403, "permission_error")
        {
        }

        /// <summary>Serialization constructor.</summary>
        protected PermissionException(SerializationInfo info, StreamingContext context)
            : base(info, context)
        {
        }
    }
}
