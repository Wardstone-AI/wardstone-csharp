namespace Wardstone.Models
{
    /// <summary>A single risk band with a level string.</summary>
    public sealed class RiskBand
    {
        /// <summary>Risk level (e.g. "Low Risk", "Some Risk", "High Risk", "Severe Risk").</summary>
        public string Level { get; }

        public RiskBand(string level)
        {
            Level = level;
        }

        public override string ToString()
        {
            return "RiskBand{Level='" + Level + "'}";
        }
    }
}
