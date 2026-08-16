using Microsoft.Data.Sqlite;

namespace Warden.Storage;

/// <summary>
/// Owns the SQLite database under %ProgramData%\Warden. Creates the schema (WAL mode) on
/// <see cref="Initialize"/> and hands out connections. Safe to use as a singleton.
/// </summary>
public sealed class WardenDb : IWardenDatabase
{
    static WardenDb() => DapperConfig.Register();

    public WardenDb() : this(null)
    {
    }

    /// <param name="databasePath">
    /// Explicit database path (used by tests). When null, defaults to &lt;WardenPaths.DataDirectory&gt;\warden.db.
    /// </param>
    public WardenDb(string? databasePath)
    {
        DatabasePath = databasePath ?? Path.Combine(Warden.Core.WardenPaths.DataDirectory, "warden.db");
    }

    public string DatabasePath { get; }

    private string ConnectionString => new SqliteConnectionStringBuilder
    {
        DataSource = DatabasePath,
        Mode = SqliteOpenMode.ReadWriteCreate,
        // Private cache: shared-cache + WAL is a documented footgun (table-level SQLITE_LOCKED between
        // threads). Concurrency comes from WAL + busy_timeout instead.
        Cache = SqliteCacheMode.Private,
    }.ToString();

    /// <summary>
    /// Opens a connection with the per-connection PRAGMAs applied: <c>busy_timeout</c> (the enforcement
    /// loop, the management handler and the process-tree writer all write concurrently, so a writer must
    /// wait rather than fail with SQLITE_BUSY) and <c>foreign_keys</c> (per-connection in SQLite).
    /// </summary>
    public SqliteConnection OpenConnection()
    {
        var connection = new SqliteConnection(ConnectionString);
        connection.Open();
        using var pragma = connection.CreateCommand();
        pragma.CommandText = "PRAGMA busy_timeout=5000; PRAGMA foreign_keys=ON;";
        pragma.ExecuteNonQuery();
        return connection;
    }

    public void Initialize()
    {
        Directory.CreateDirectory(Path.GetDirectoryName(DatabasePath)!);
        using var connection = OpenConnection();

        using (var pragma = connection.CreateCommand())
        {
            pragma.CommandText = "PRAGMA journal_mode=WAL;";
            pragma.ExecuteNonQuery();
        }

        using (var cmd = connection.CreateCommand())
        {
            cmd.CommandText = Schema;
            cmd.ExecuteNonQuery();
        }

        // Migrations are destructive (they collapse rows) — run them atomically so a failure part-way
        // through cannot leave the table de-duplicated but without its uniqueness guarantee.
        using var tx = connection.BeginTransaction();
        using (var migrate = connection.CreateCommand())
        {
            migrate.Transaction = tx;
            migrate.CommandText = Migrations;
            migrate.ExecuteNonQuery();
        }
        tx.Commit();
    }

    /// <summary>
    /// Idempotent schema upgrades applied after <see cref="Schema"/>. There is no migration framework
    /// here by design: each statement must be safe to run on both a fresh and an existing database.
    /// </summary>
    private const string Migrations = """
        -- The whitelist is the CURRENT decision per file, not a verdict log: one row per SHA-256.
        -- Earlier builds inserted a row per evaluation, so the same file accumulated duplicates.
        -- Collapse them (keeping the newest row per hash) before enforcing uniqueness.
        DELETE FROM whitelist
        WHERE Id NOT IN (SELECT MAX(Id) FROM whitelist GROUP BY Sha256 COLLATE NOCASE);

        DROP INDEX IF EXISTS IX_whitelist_sha256;
        CREATE UNIQUE INDEX IF NOT EXISTS UX_whitelist_sha256 ON whitelist(Sha256 COLLATE NOCASE);
        """;

    // Column names match the entity property names so Dapper maps them directly (no underscore config).
    private const string Schema = """
        CREATE TABLE IF NOT EXISTS whitelist (
            Id             INTEGER PRIMARY KEY AUTOINCREMENT,
            Timestamp      TEXT    NOT NULL,
            Action         INTEGER NOT NULL,
            ProcessName    TEXT    NOT NULL,
            ProcessPath    TEXT    NOT NULL,
            Sha256         TEXT    NOT NULL,
            SignerSubject  TEXT,
            SignerIssuer   TEXT,
            CertThumbprint TEXT,
            LlmVerdict     TEXT,
            MlScore        REAL,
            CommandLine    TEXT    NOT NULL DEFAULT '',
            FileSize       INTEGER NOT NULL DEFAULT -1,
            ParentName     TEXT,
            ParentPath     TEXT,
            Source         TEXT    NOT NULL,
            RuleId         INTEGER
        );
        -- The uniqueness of Sha256 is established in Migrations (existing databases need de-duping first).

        CREATE TABLE IF NOT EXISTS rules (
            Id               INTEGER PRIMARY KEY AUTOINCREMENT,
            Kind             INTEGER NOT NULL,
            MatchValue       TEXT    NOT NULL,
            Action           INTEGER NOT NULL,
            RequireSignature INTEGER NOT NULL DEFAULT 0,
            RequireWhitelist INTEGER NOT NULL DEFAULT 0,
            Enabled          INTEGER NOT NULL DEFAULT 1,
            CreatedTs        TEXT    NOT NULL,
            Note             TEXT
        );

        CREATE TABLE IF NOT EXISTS command_lines (
            Id           INTEGER PRIMARY KEY AUTOINCREMENT,
            Timestamp    TEXT    NOT NULL,
            Pid          INTEGER NOT NULL,
            ParentPid    INTEGER NOT NULL,
            ImagePath    TEXT    NOT NULL,
            Sha256       TEXT,
            CommandLine  TEXT    NOT NULL,
            IsScript     INTEGER NOT NULL DEFAULT 0,
            Verdict      INTEGER,
            VerdictSource TEXT
        );

        CREATE TABLE IF NOT EXISTS quarantine (
            Id             INTEGER PRIMARY KEY AUTOINCREMENT,
            OriginalPath   TEXT    NOT NULL,
            QuarantinePath TEXT    NOT NULL,
            Sha256         TEXT,
            Size           INTEGER,
            Timestamp      TEXT    NOT NULL,
            Reason         TEXT,
            RestoreAclSddl TEXT,
            VerdictSource  TEXT,
            Restored       INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS wdac_policy_log (
            Id         INTEGER PRIMARY KEY AUTOINCREMENT,
            Timestamp  TEXT    NOT NULL,
            Action     TEXT    NOT NULL,
            RuleAdded  TEXT,
            CipGuid    TEXT,
            BackupPath TEXT
        );

        CREATE TABLE IF NOT EXISTS settings (
            Key   TEXT PRIMARY KEY,
            Value TEXT
        );

        CREATE TABLE IF NOT EXISTS attack_chains (
            Id             INTEGER PRIMARY KEY AUTOINCREMENT,
            SessionGuid    TEXT    NOT NULL,
            NodePid        INTEGER NOT NULL,
            ParentPid      INTEGER NOT NULL,
            ImagePath      TEXT    NOT NULL,
            Sha256         TEXT,
            CommandLine    TEXT    NOT NULL DEFAULT '',
            Timestamp      TEXT    NOT NULL,
            Depth          INTEGER NOT NULL DEFAULT 0,
            SuspicionScore REAL    NOT NULL DEFAULT 0,
            LlmRationale   TEXT
        );
        CREATE INDEX IF NOT EXISTS IX_attack_chains_session ON attack_chains(SessionGuid);

        CREATE TABLE IF NOT EXISTS protected_folders (
            Id          INTEGER PRIMARY KEY AUTOINCREMENT,
            Path        TEXT    NOT NULL,
            Recursive   INTEGER NOT NULL DEFAULT 1,
            MonitorMode TEXT    NOT NULL DEFAULT 'monitor',
            AddedTs     TEXT    NOT NULL
        );

        CREATE TABLE IF NOT EXISTS reputation_cache (
            Sha256      TEXT PRIMARY KEY,
            VtPositives INTEGER NOT NULL DEFAULT 0,
            VtTotal     INTEGER NOT NULL DEFAULT 0,
            VtFirstSeen TEXT,
            CachedTs    TEXT    NOT NULL,
            TtlSecs     INTEGER NOT NULL DEFAULT 86400
        );

        CREATE TABLE IF NOT EXISTS vulnerable_apps (
            Id                  INTEGER PRIMARY KEY AUTOINCREMENT,
            AppPath             TEXT    NOT NULL,
            Publisher           TEXT,
            Reason              TEXT    NOT NULL,
            MitigationProfileId INTEGER,
            FwInBlocked         INTEGER NOT NULL DEFAULT 0,
            FwOutBlocked        INTEGER NOT NULL DEFAULT 0
        );
        CREATE UNIQUE INDEX IF NOT EXISTS UX_vulnerable_apps_path ON vulnerable_apps(AppPath);

        CREATE TABLE IF NOT EXISTS mitigation_profiles (
            Id               INTEGER PRIMARY KEY AUTOINCREMENT,
            AppPath          TEXT    NOT NULL,
            XmlPath          TEXT,
            AsrGuidsCsv      TEXT,
            NoChildProcesses INTEGER NOT NULL DEFAULT 0,
            CetUsermode      INTEGER NOT NULL DEFAULT 0,
            AppliedTs        TEXT    NOT NULL
        );
        CREATE UNIQUE INDEX IF NOT EXISTS UX_mitigation_profiles_path ON mitigation_profiles(AppPath);

        CREATE TABLE IF NOT EXISTS firewall_rules (
            Id         INTEGER PRIMARY KEY AUTOINCREMENT,
            AppPath    TEXT    NOT NULL,
            Direction  TEXT    NOT NULL,
            FwRuleName TEXT    NOT NULL,
            Enabled    INTEGER NOT NULL DEFAULT 1,
            CreatedTs  TEXT    NOT NULL
        );
        CREATE INDEX IF NOT EXISTS IX_firewall_rules_app ON firewall_rules(AppPath);

        CREATE TABLE IF NOT EXISTS webapp_classifications (
            Id               INTEGER PRIMARY KEY AUTOINCREMENT,
            AppPath          TEXT    NOT NULL,
            Engine           TEXT    NOT NULL,
            StaticScore      INTEGER NOT NULL DEFAULT 0,
            RuntimeConfirmed INTEGER NOT NULL DEFAULT 0,
            SignalsJson      TEXT,
            Ts               TEXT    NOT NULL
        );
        CREATE UNIQUE INDEX IF NOT EXISTS UX_webapp_classifications_path ON webapp_classifications(AppPath);

        CREATE TABLE IF NOT EXISTS tamper_log (
            Id        INTEGER PRIMARY KEY AUTOINCREMENT,
            Timestamp TEXT    NOT NULL,
            Category  TEXT    NOT NULL,
            Detail    TEXT,
            Severity  TEXT    NOT NULL DEFAULT 'warning'
        );
        """;
}
