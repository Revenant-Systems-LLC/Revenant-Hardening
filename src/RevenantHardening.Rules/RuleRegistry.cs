using RevenantHardening.Core;
using RevenantHardening.Rules.Execution;
using RevenantHardening.Rules.Msix;
using RevenantHardening.Rules.Registry;
using RevenantHardening.Rules.Secrets;

namespace RevenantHardening.Rules;

public static class RuleRegistry
{
    public static readonly IReadOnlyList<IRule> All =
    [
        // RSH-MSIX-*
        new MsixCapabilityRule(),
        new RunFullTrustRule(),
        new DebugSigningRule(),

        // RSH-REG-*
        new HklmWriteRule(),
        new WritableHandleRule(),
        new ElevationGuardRule(),

        // RSH-EXEC-*
        new ProcessStartRule(),
        new UseShellExecuteRule(),
        new AssemblyLoadRule(),
        new UriHandlerRule(),

        // RSH-SEC-*
        new ApiKeyPatternRule(),
        new ResourceSecretRule(),
        new ProjectMetadataSecretRule(),
    ];
}
