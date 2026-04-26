using RevenantHardening.Core.Models;

namespace RevenantHardening.Core;

public interface IRule
{
    RuleMetadata Metadata { get; }
    IEnumerable<Finding> Analyze(FileContext context);
}
