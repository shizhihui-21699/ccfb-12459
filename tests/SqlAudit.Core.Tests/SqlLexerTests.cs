using SqlAudit.Core.Model;
using SqlAudit.Core.Sql;

namespace SqlAudit.Core.Tests;

public class SqlLexerTests
{
    [Fact]
    public void StringWithSemicolonIsOneToken()
    {
        var tokens = SqlLexer.Tokenize("SELECT * FROM t WHERE name = 'a;b'", SqlDialect.MySql);
        var strings = tokens.Where(t => t.Kind == TokKind.String).ToList();
        Assert.Single(strings);
        Assert.Equal("a;b", strings[0].Value);
    }

    [Fact]
    public void MySqlBackslashEscapeIsHandled()
    {
        var tokens = SqlLexer.Tokenize(@"SELECT 'it\'s ok'", SqlDialect.MySql);
        var s = tokens.Single(t => t.Kind == TokKind.String);
        Assert.Equal("it's ok", s.Value);
    }

    [Fact]
    public void PostgreSqlBackslashIsLiteral()
    {
        // PG 标准字符串中反斜杠不是转义符，'a\' 应当在第二个引号处结束
        var tokens = SqlLexer.Tokenize(@"SELECT 'a\'", SqlDialect.PostgreSql);
        var s = tokens.Single(t => t.Kind == TokKind.String);
        Assert.Equal(@"a\", s.Value);
    }

    [Fact]
    public void MySqlExecutableCommentIsDistinguished()
    {
        var tokens = SqlLexer.Tokenize("SELECT /*!50000 1 */", SqlDialect.MySql);
        var comment = tokens.Single(t => t.Kind == TokKind.ExecutableComment);
        Assert.Contains("50000", comment.Text);
        Assert.Equal(" 1 ", comment.Value);
    }

    [Fact]
    public void PlainBlockCommentIsNotExecutable()
    {
        var tokens = SqlLexer.Tokenize("SELECT /* normal */ 1", SqlDialect.MySql);
        Assert.Contains(tokens, t => t.Kind == TokKind.Comment);
        Assert.DoesNotContain(tokens, t => t.Kind == TokKind.ExecutableComment);
    }

    [Fact]
    public void PostgreSqlDollarQuotedBodyIsSingleString()
    {
        const string sql = "SELECT $$ body with ; semicolon $$";
        var tokens = SqlLexer.Tokenize(sql, SqlDialect.PostgreSql);
        var s = tokens.Single(t => t.Kind == TokKind.String);
        Assert.Contains("semicolon", s.Value);
    }

    [Fact]
    public void PostgreSqlTaggedDollarQuoteIsHandled()
    {
        const string sql = "SELECT $tag$ x $$ y $tag$";
        var tokens = SqlLexer.Tokenize(sql, SqlDialect.PostgreSql);
        var s = tokens.Single(t => t.Kind == TokKind.String);
        Assert.Equal(" x $$ y ", s.Value);
    }

    [Fact]
    public void NestedBlockCommentInPostgreSql()
    {
        var tokens = SqlLexer.Tokenize("SELECT 1 /* outer /* inner */ still */ + 2", SqlDialect.PostgreSql);
        Assert.Contains(tokens, t => t.Kind == TokKind.Comment);
        // 注释全部吞掉后不应残留 inner 的标识符
        Assert.DoesNotContain(tokens, t => t.IsKeyword("inner"));
    }

    [Fact]
    public void MySqlHashCommentIsComment()
    {
        var tokens = SqlLexer.Tokenize("SELECT 1 # comment\n+ 2", SqlDialect.MySql);
        Assert.Contains(tokens, t => t.Kind == TokKind.Comment);
    }

    [Fact]
    public void HexAndBitLiteralsAreRecognized()
    {
        var tokens = SqlLexer.Tokenize("SELECT 0x4142, 0b1010, x'41'", SqlDialect.MySql);
        // 0x4142 与 x'41' 都是十六进制字面量，0b1010 是位串
        Assert.Equal(2, tokens.Count(t => t.Kind == TokKind.HexLiteral));
        Assert.Equal(1, tokens.Count(t => t.Kind == TokKind.BitLiteral));
    }

    [Fact]
    public void SystemVariablesAreSingleTokens()
    {
        var tokens = SqlLexer.Tokenize("SELECT @@global.max_connections", SqlDialect.MySql);
        var v = tokens.Single(t => t.Kind == TokKind.Variable);
        Assert.Equal("@@global.max_connections", v.Text);
    }

    [Fact]
    public void DoubleDashNeedsWhitespaceInMySql()
    {
        // MySQL 中 5--3 是 5 - (-3)，不是注释
        var tokens = SqlLexer.Tokenize("SELECT 5--3", SqlDialect.MySql);
        Assert.DoesNotContain(tokens, t => t.Kind == TokKind.Comment);
    }

    [Fact]
    public void UnterminatedQuoteDoesNotHangOrThrow()
    {
        var tokens = SqlLexer.Tokenize("SELECT 'unterminated", SqlDialect.MySql);
        Assert.Contains(tokens, t => t.Kind == TokKind.String);
    }
}

public class SqlStatementSplitterTests
{
    [Fact]
    public void SplitsTwoStatements()
    {
        var segs = SqlStatementSplitter.Split("SELECT 1; SELECT 2", SqlDialect.MySql);
        Assert.Equal(2, segs.Count);
        Assert.Equal("SELECT 1", segs[0].Sql);
    }

    [Fact]
    public void SemicolonInsideStringDoesNotSplit()
    {
        var segs = SqlStatementSplitter.Split("SELECT * FROM t WHERE a = 'x;y'", SqlDialect.MySql);
        Assert.Single(segs);
    }

    [Fact]
    public void SemicolonInsidePostgresDollarQuoteDoesNotSplit()
    {
        var segs = SqlStatementSplitter.Split(
            "CREATE FUNCTION f() RETURNS int AS $$ BEGIN RETURN 1; END $$ LANGUAGE plpgsql",
            SqlDialect.PostgreSql);
        Assert.Single(segs);
    }

    [Fact]
    public void RoutineDefinitionBodyIsNotSplit()
    {
        const string sql = "CREATE PROCEDURE p() BEGIN SELECT 1; SELECT 2; END";
        var segs = SqlStatementSplitter.Split(sql, SqlDialect.MySql);
        Assert.Single(segs);
    }

    [Fact]
    public void TrailingSemicolonDoesNotCreateEmptyStatement()
    {
        var segs = SqlStatementSplitter.Split("SELECT 1;", SqlDialect.MySql);
        Assert.Single(segs);
    }

    [Fact]
    public void CommentsArePreservedInSegments()
    {
        var segs = SqlStatementSplitter.Split("SELECT 1 -- trailing\n; SELECT 2", SqlDialect.MySql);
        Assert.Equal(2, segs.Count);
    }
}

public class SqlFingerprintTests
{
    [Fact]
    public void SameShapeDifferentLiteralsProduceSameHash()
    {
        var a = SqlFingerprint.Compute("SELECT * FROM users WHERE id = 1", SqlDialect.MySql);
        var b = SqlFingerprint.Compute("SELECT * FROM users WHERE id = 999", SqlDialect.MySql);
        Assert.Equal(a, b);
    }

    [Fact]
    public void DifferentStructureProducesDifferentHash()
    {
        var a = SqlFingerprint.Compute("SELECT * FROM users WHERE id = 1", SqlDialect.MySql);
        var b = SqlFingerprint.Compute("SELECT * FROM orders WHERE id = 1", SqlDialect.MySql);
        Assert.NotEqual(a, b);
    }

    [Fact]
    public void UnicodeSqlDoesNotBreakHashing()
    {
        var hash = SqlFingerprint.Compute("SELECT * FROM 用户表 WHERE 名称 = '张三'", SqlDialect.MySql);
        Assert.Equal(16, hash.Length);
    }
}
