namespace Warden.Hardening;

/// <summary>
/// The security descriptors used to self-protect the agent <b>without PPL</b> (Protected Process Light /
/// ELAM require a Microsoft AV-vendor agreement and are explicitly out of scope). Pure string constants —
/// applying them (via <see cref="DataDirectoryHardener"/> or the installer's <c>sc sdset</c>) is what
/// makes the real change. Kept together so they can be reviewed and unit-tested in one place.
/// </summary>
public static class HardeningSddl
{
    /// <summary>
    /// Data directory DACL: protected (no inheritance from the parent), full control inherited by
    /// children, granted to Local System (SY) and Builtin Administrators (BA) only. Standard users get
    /// nothing — they cannot read the database or tamper with the agent's on-disk state.
    /// </summary>
    public const string DataDirectoryDacl = "D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";

    /// <summary>Database-file DACL: protected full control to SYSTEM + Administrators only (no inherit flags).</summary>
    public const string DataFileDacl = "D:PAI(A;;FA;;;SY)(A;;FA;;;BA)";

    /// <summary>
    /// Service DACL for <c>sc sdset</c>: SYSTEM (SY) and Administrators (BA) get full service control;
    /// Authenticated Users (AU) may only query config/status, enumerate dependents, interrogate, and read
    /// the descriptor — they are denied SERVICE_START/STOP/PAUSE, CHANGE_CONFIG, and DELETE. This is what
    /// stops a standard user from stopping or deleting the agent.
    /// </summary>
    /// <remarks>
    /// SDDL service rights: CC=QueryConfig, DC=ChangeConfig, LC=QueryStatus, SW=EnumerateDependents,
    /// RP=Start, WP=Stop, DT=Pause/Continue, LO=Interrogate, CR=UserDefinedControl; SD=Delete,
    /// RC=ReadControl, WD=WriteDac, WO=WriteOwner.
    /// </remarks>
    public const string ServiceDacl =
        "D:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;AU)";
}
