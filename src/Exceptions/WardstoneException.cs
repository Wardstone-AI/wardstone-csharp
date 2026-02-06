using System;
using System.Runtime.Serialization;

namespace Wardstone.Exceptions
{
    /// <summary>
    /// Base exception for all Wardstone SDK errors.
    /// </summary>
    [Serializable]
    public class WardstoneException : Exception
    {
        /// <summary>HTTP status code, or null for non-HTTP errors.</summary>
        public int? Status { get; }

        /// <summary>Machine-readable error code, or null if unavailable.</summary>
        public string Code { get; }

        public WardstoneException(string message)
            : this(message, null, null)
        {
        }

        public WardstoneException(string message, int? status, string code)
            : base(message)
        {
            Status = status;
            Code = code;
        }

        /// <summary>Serialization constructor with validation on deserialized fields.</summary>
        protected WardstoneException(SerializationInfo info, StreamingContext context)
            : base(info, context)
        {
            if (info.GetBoolean("HasStatus"))
            {
                int s = info.GetInt32("Status");
                // Validate deserialized Status is within valid HTTP status code range
                Status = (s >= 100 && s <= 599) ? (int?)s : null;
            }
            string code = info.GetString("Code");
            // Validate deserialized Code to prevent oversized or injected strings
            if (code != null && code.Length > 200)
            {
                code = code.Substring(0, 200);
            }
            Code = code;
        }

        /// <summary>Custom serialization to include Status and Code.</summary>
        public override void GetObjectData(SerializationInfo info, StreamingContext context)
        {
            base.GetObjectData(info, context);
            info.AddValue("HasStatus", Status.HasValue);
            if (Status.HasValue)
            {
                info.AddValue("Status", Status.Value);
            }
            info.AddValue("Code", Code);
        }
    }
}
