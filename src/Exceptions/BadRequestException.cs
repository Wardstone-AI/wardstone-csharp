using System;
using System.Runtime.Serialization;

namespace Wardstone.Exceptions
{
    /// <summary>
    /// Thrown on HTTP 400 responses or client-side input validation failures.
    /// </summary>
    [Serializable]
    public class BadRequestException : WardstoneException
    {
        /// <summary>Maximum allowed text length, present when code is "text_too_long".</summary>
        public int? MaxLength { get; }

        public BadRequestException(string message)
            : this(message, null, null)
        {
        }

        public BadRequestException(string message, string code, int? maxLength)
            : base(message, 400, code ?? "bad_request")
        {
            MaxLength = maxLength;
        }

        /// <summary>Serialization constructor.</summary>
        protected BadRequestException(SerializationInfo info, StreamingContext context)
            : base(info, context)
        {
            if (info.GetBoolean("HasMaxLength"))
            {
                int ml = info.GetInt32("MaxLength");
                MaxLength = (ml > 0 && ml <= 8_000_000) ? (int?)ml : null;
            }
        }

        /// <summary>Custom serialization to include MaxLength.</summary>
        public override void GetObjectData(SerializationInfo info, StreamingContext context)
        {
            base.GetObjectData(info, context);
            info.AddValue("HasMaxLength", MaxLength.HasValue);
            if (MaxLength.HasValue)
            {
                info.AddValue("MaxLength", MaxLength.Value);
            }
        }
    }
}
