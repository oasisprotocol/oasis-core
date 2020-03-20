package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:  "debugcover FILE",
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cmd.SilenceUsage = true
		fileName := args[0]
		profiles, err := ParseProfiles(fileName)
		if err != nil {
			return fmt.Errorf("ParseProfiles %s: %w", fileName, err)
		}
		fmt.Printf("profiles: %#v\n", profiles)
		return nil
	},
}

func main() {
	_ = rootCmd.Execute()
}
