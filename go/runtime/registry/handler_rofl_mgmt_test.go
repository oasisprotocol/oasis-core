package registry

import "testing"

func TestValidBundleTemporaryName(t *testing.T) {
	tests := []struct {
		name  string
		input string
		valid bool
	}{
		{
			name:  "valid lowercase",
			input: "instance-1a2b3c",
			valid: true,
		},
		{
			name:  "valid uppercase",
			input: "INSTANCE-ABC123",
			valid: true,
		},
		{
			name:  "valid mixed case",
			input: "Instance-AbC123",
			valid: true,
		},
		{
			name:  "valid without hyphen",
			input: "instance123",
			valid: true,
		},
		{
			name:  "invalid underscore",
			input: "instance_1a2b3c",
			valid: false,
		},
		{
			name:  "invalid dot",
			input: "instance.1a2b3c",
			valid: false,
		},
		{
			name:  "invalid space",
			input: "instance 1a2b3c",
			valid: false,
		},
		{
			name:  "invalid empty",
			input: "",
			valid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := validBundleTemporaryName.MatchString(tt.input)
			if got != tt.valid {
				t.Errorf(
					"validBundleTemporaryName.MatchString(%q) = %v, want %v",
					tt.input,
					got,
					tt.valid,
				)
			}
		})
	}
}
