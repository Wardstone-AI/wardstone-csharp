using System;
using System.Diagnostics;
using System.Runtime.Serialization;

namespace Wardstone
{
    /// <summary>
    /// Configuration options for <see cref="WardstoneClient"/>.
    /// This class must not be serialized as it may contain an API key.
    /// </summary>
    // [Serializable] is required so that ISerializable.GetObjectData is invoked by BinaryFormatter.
    // The ISerializable implementation throws to block serialization (API key protection).
    [Serializable]
    public sealed class WardstoneClientOptions : ISerializable
    {
        [NonSerialized]
        [DebuggerBrowsable(DebuggerBrowsableState.Never)]
        private string _apiKey;

        /// <summary>Your Wardstone API key. Falls back to the WARDSTONE_API_KEY environment variable.</summary>
        public string ApiKey
        {
            internal get { return _apiKey; }
            set { _apiKey = value; }
        }

        /// <summary>Base URL for the API. Defaults to "https://wardstone.ai".</summary>
        public string BaseUrl { get; set; }

        /// <summary>Request timeout. Defaults to 30 seconds.</summary>
        public TimeSpan? Timeout { get; set; }

        /// <summary>Maximum number of retries on 429/5xx errors. Defaults to 2.</summary>
        public int? MaxRetries { get; set; }

        public WardstoneClientOptions()
        {
        }

        /// <summary>Prevents serialization which could write the API key to disk/network.</summary>
        void ISerializable.GetObjectData(SerializationInfo info, StreamingContext context)
        {
            throw new SerializationException("WardstoneClientOptions cannot be serialized (API key protection).");
        }

        /// <summary>Prevents deserialization.</summary>
        private WardstoneClientOptions(SerializationInfo info, StreamingContext context)
        {
            throw new SerializationException("WardstoneClientOptions cannot be deserialized (API key protection).");
        }

        /// <summary>Prevents API key from appearing in ToString() output.</summary>
        public override string ToString()
        {
            return "WardstoneClientOptions{BaseUrl='" + BaseUrl
                + "', Timeout=" + Timeout
                + ", MaxRetries=" + MaxRetries + "}";
        }
    }
}
