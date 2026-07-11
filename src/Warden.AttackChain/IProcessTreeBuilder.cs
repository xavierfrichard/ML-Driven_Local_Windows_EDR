using Warden.Core;
using Warden.Etw;

namespace Warden.AttackChain;

/// <summary>
/// Maintains a live process tree from process-start events and reconstructs the ancestry chain for a
/// given process. Also persists observed chains for the Attack Chains panel and scores each node's
/// suspicion heuristically (the LLM analyst refines this in Phase 4).
/// </summary>
public interface IProcessTreeBuilder
{
    /// <summary>Records a process start (called from the ETW thread). Persists the node and updates the tree.</summary>
    void RecordStart(ProcessStartRecord start);

    /// <summary>
    /// Reconstructs the ancestry chain for <paramref name="pid"/> (nearest-parent last) as a
    /// <see cref="AttackChainNode"/> suitable for <see cref="VerdictContext.Chain"/>. Returns
    /// <see cref="AttackChainNode.None"/> if the process is unknown.
    /// </summary>
    AttackChainNode BuildChainFor(int pid);
}
