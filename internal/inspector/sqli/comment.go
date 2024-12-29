package sqli

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/xwb1989/sqlparser"
)

var (
	// This may not be the best approach...
	lineCommentPattern  = regexp.MustCompile(`(?i)(#|--)\s*(AND|OR|UNION|SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|TRUNCATE)`)
	blockCommentPattern = regexp.MustCompile(`(?i)/\*.*?(AND|OR|UNION|SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|TRUNCATE).*?\*/`)
)

func IsQueryCommentInjection(query string) error {
	comments := extractComments(query)

	for _, comment := range comments {
		normalizedValue := strings.TrimSpace(comment)

		if lineCommentPattern.MatchString(normalizedValue) || blockCommentPattern.MatchString(normalizedValue) {
			return fmt.Errorf("SQLi detected")
		}
	}

	return nil
}

func extractComments(query string) []string {
	var comments []string
	tokenizer := sqlparser.NewStringTokenizer(query)

	for {
		token, value := tokenizer.Scan()
		if token == 0 {
			break
		}

		if token == sqlparser.COMMENT {
			comments = append(comments, string(value))
		}
	}

	return comments
}
