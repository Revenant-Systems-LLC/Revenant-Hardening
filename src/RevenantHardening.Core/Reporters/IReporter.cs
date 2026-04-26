using RevenantHardening.Core.Models;

namespace RevenantHardening.Core.Reporters;

public interface IReporter
{
    void Report(ScanResult result, TextWriter output);
}
