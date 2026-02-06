namespace Wardstone.Models
{
    /// <summary>Container for all four risk band categories.</summary>
    public sealed class RiskBands
    {
        public RiskBand ContentViolation { get; }
        public RiskBand PromptAttack { get; }
        public RiskBand DataLeakage { get; }
        public RiskBand UnknownLinks { get; }

        public RiskBands(RiskBand contentViolation, RiskBand promptAttack,
                         RiskBand dataLeakage, RiskBand unknownLinks)
        {
            ContentViolation = contentViolation;
            PromptAttack = promptAttack;
            DataLeakage = dataLeakage;
            UnknownLinks = unknownLinks;
        }

        public override string ToString()
        {
            return "RiskBands{ContentViolation=" + ContentViolation
                + ", PromptAttack=" + PromptAttack
                + ", DataLeakage=" + DataLeakage
                + ", UnknownLinks=" + UnknownLinks + "}";
        }
    }
}
