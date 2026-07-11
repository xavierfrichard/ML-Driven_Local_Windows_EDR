using System.Data;
using System.Globalization;
using Dapper;

namespace Warden.Storage;

/// <summary>Dapper type handlers. SQLite has no native DateTimeOffset, so we round-trip it as ISO-8601 text.</summary>
public static class DapperConfig
{
    private static bool _registered;
    private static readonly object Gate = new();

    /// <summary>Registers the custom type handlers exactly once.</summary>
    public static void Register()
    {
        lock (Gate)
        {
            if (_registered)
            {
                return;
            }
            SqlMapper.AddTypeHandler(new DateTimeOffsetHandler());
            _registered = true;
        }
    }

    private sealed class DateTimeOffsetHandler : SqlMapper.TypeHandler<DateTimeOffset>
    {
        public override void SetValue(IDbDataParameter parameter, DateTimeOffset value)
        {
            parameter.DbType = DbType.String;
            parameter.Value = value.ToString("O", CultureInfo.InvariantCulture);
        }

        public override DateTimeOffset Parse(object value) => value switch
        {
            string s => DateTimeOffset.Parse(s, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind),
            DateTimeOffset dto => dto,
            DateTime dt => new DateTimeOffset(dt),
            _ => throw new DataException($"Cannot convert {value?.GetType().Name ?? "null"} to DateTimeOffset."),
        };
    }
}
