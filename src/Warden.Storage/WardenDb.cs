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
    /// Explicit database path (used by tests). When null, defaults to %ProgramData%\Warden\warden.db.
    /// </param>
    public WardenDb(string? databasePath)
    {
        DatabasePath = databasePath ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "Warden", "warden.db");
    }

    public string DatabasePath { get; }

    private string ConnectionString => new SqliteConnectionStringBuilder
    {
        DataSource = DatabasePath,
        Mode = SqliteOpenMode.ReadWriteCreate,
        Cache = SqliteCacheMode.Shared,
    }.ToString();

    public SqliteConnection OpenConnection()
    {
        var connection = new SqliteConnection(ConnectionString);
        connection.Open();
        return connection;
    }

    public void Initialize()
    {
        Directory.CreateDirectory(Path.GetDirectoryName(DatabasePath)!);
        using var connection = OpenConnection();

        using (var pragma = connection.CreateCommand())
        {
            pragma.CommandText = "PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;";
            pragma.ExecuteNonQuery();
        }

        using var cmd = connection.CreateCommand();
        cmd.CommandText = Schema;
        cmd.ExecuteNonQuery();
    }

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
        CREATE INDEX IF NOT EXISTS IX_whitelist_sha256 ON whitelist(Sha256);

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
        """;
}
