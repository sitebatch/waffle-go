package main

import (
	"os"

	"github.com/sitebatch/waffle-go/internal/rule"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use: "waffle",
}

var dumpDefaultRulesCmd = &cobra.Command{
	Use: "dump-default-rules",
	Run: func(cmd *cobra.Command, args []string) {
		os.Stdout.Write(rule.DefaultRawRules())
	},
}

func main() {
	rootCmd.AddCommand(dumpDefaultRulesCmd)
	rootCmd.Execute()
}
