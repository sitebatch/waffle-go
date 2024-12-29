package sqli

import (
	"fmt"

	"github.com/xwb1989/sqlparser"
)

// IsWhereTautologyFull checks if the given SQL query is a tautology.
func IsWhereTautologyFull(sql string) (bool, error) {
	stmt, err := sqlparser.Parse(sql)
	if err != nil {
		return false, fmt.Errorf("failed to parse SQL: %w", err)
	}

	selectStmt, ok := stmt.(*sqlparser.Select)
	if !ok || selectStmt.Where == nil {
		return false, nil
	}

	return checkExprForTautology(selectStmt.Where.Expr), nil
}

func checkExprForTautology(expr sqlparser.Expr) bool {
	switch e := expr.(type) {
	case *sqlparser.AndExpr:
		return checkExprForTautology(e.Left) || checkExprForTautology(e.Right)
	case *sqlparser.OrExpr:
		return checkExprForTautology(e.Left) || checkExprForTautology(e.Right)
	case *sqlparser.ComparisonExpr:
		return isComparisonTautology(e)
	case *sqlparser.ParenExpr:
		return checkExprForTautology(e.Expr)
	}
	return false
}

func isComparisonTautology(expr *sqlparser.ComparisonExpr) bool {
	// Check for patterns like "1 = 1", "TRUE = TRUE", etc.
	if isLiteralOrBoolean(expr.Left) && isLiteralOrBoolean(expr.Right) {
		return expr.Operator == "=" || expr.Operator == "!=" || expr.Operator == "<>"
	}

	// Check for patterns like "column = column"
	if isColumn(expr.Left) && isColumn(expr.Right) {
		leftCol := expr.Left.(*sqlparser.ColName)
		rightCol := expr.Right.(*sqlparser.ColName)
		return leftCol.Name.String() == rightCol.Name.String() && expr.Operator == "="
	}

	return false
}

func isLiteralOrBoolean(expr sqlparser.Expr) bool {
	switch e := expr.(type) {
	case *sqlparser.SQLVal:
		return e.Type == sqlparser.IntVal || e.Type == sqlparser.StrVal
	case sqlparser.BoolVal:
		return true
	}
	return false
}

func isColumn(expr sqlparser.Expr) bool {
	_, ok := expr.(*sqlparser.ColName)
	return ok
}
