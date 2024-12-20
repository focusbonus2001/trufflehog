package hwcloud

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/engine/ahocorasick"
)

func TestHwcloud_Pattern(t *testing.T) {
	d := Scanner{}
	ahoCorasickCore := ahocorasick.NewAhoCorasickCore([]detectors.Detector{d})
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "typical pattern",
			input: "hcloud_token = 'ZT3QVRN7AVKAZ2ULCULT'; ZT3QVRN7AVKAZ2ULCULTZT3QVRN7AVKAZ2ULCULT",
			want:  []string{"ak:ZT3QVRN7AVKAZ2ULCULT,sk:ZT3QVRN7AVKAZ2ULCULTZT3QVRN7AVKAZ2ULCULT"},
		},
		// 		{
		// 			name: "finds all matches",
		// 			input: `hwcloud_token1 = '3aBcDFE5678901234567890_1a2b3c4d'
		// hwcloud_token2 = '3aDcDFE56789012245678a0_1a2b3c2d'`,
		// 			want: []string{"3aBcDFE5678901234567890_1a2b3c4d", "3aDcDFE56789012245678a0_1a2b3c2d"},
		// 		},
		// 		{
		// 			name:  "invalid pattern",
		// 			input: "hwcloud_token = '1a2b3c4d'",
		// 			want:  []string{},
		// 		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			matchedDetectors := ahoCorasickCore.FindDetectorMatches([]byte(test.input))
			if len(matchedDetectors) == 0 {
				t.Errorf("keywords '%v' not matched by: %s", d.Keywords(), test.input)
				return
			}

			results, err := d.FromData(context.Background(), false, []byte(test.input))
			if err != nil {
				t.Errorf("error = %v", err)
				return
			}

			if len(results) != len(test.want) {
				if len(results) == 0 {
					t.Errorf("did not receive result")
				} else {
					t.Errorf("expected %d results, only received %d", len(test.want), len(results))
				}
				return
			}

			actual := make(map[string]struct{}, len(results))
			for _, r := range results {
				if len(r.RawV2) > 0 {
					actual[string(r.RawV2)] = struct{}{}
				} else {
					actual[string(r.Raw)] = struct{}{}
				}
			}
			expected := make(map[string]struct{}, len(test.want))
			for _, v := range test.want {
				expected[v] = struct{}{}
			}

			if diff := cmp.Diff(expected, actual); diff != "" {
				t.Errorf("%s diff: (-want +got)\n%s", test.name, diff)
			}
		})
	}
}