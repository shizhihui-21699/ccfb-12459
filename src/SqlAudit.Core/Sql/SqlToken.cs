namespace SqlAudit.Core.Sql;

public enum TokKind
{
    Identifier,
    QuotedIdentifier,
    String,
    Number,
    HexLiteral,
    BitLiteral,
    Variable,
    Operator,
    Punctuation,
    Semicolon,
    Comment,
    ExecutableComment,
    Placeholder,
}

/// <summary>SQL 词法单元。</summary>
public readonly record struct SqlToken(
    TokKind Kind,
    string Text,
    string Value,
    int Offset,
    int Length)
{
    public int End => Offset + Length;

    public bool IsKeyword(string keyword) =>
        Kind == TokKind.Identifier && string.Equals(Value, keyword, StringComparison.OrdinalIgnoreCase);

    public bool IsOperator(string op) =>
        Kind == TokKind.Operator && Text == op;

    public bool IsPunct(char c) =>
        Kind == TokKind.Punctuation && Text.Length == 1 && Text[0] == c;

    public bool IsAnyIdentifier(string name) =>
        (Kind == TokKind.Identifier || Kind == TokKind.QuotedIdentifier)
        && string.Equals(Value, name, StringComparison.OrdinalIgnoreCase);

    public bool IsLiteral => Kind is TokKind.String or TokKind.Number or TokKind.HexLiteral or TokKind.BitLiteral;

    public override string ToString() => $"{Kind}:{Text}@{Offset}";
}
