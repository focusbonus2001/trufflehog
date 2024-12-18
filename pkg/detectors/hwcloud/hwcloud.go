package hwcloud

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"

	regexp "github.com/wasilibs/go-re2"

	"github.com/trufflesecurity/trufflehog/v3/pkg/common"
	"github.com/trufflesecurity/trufflehog/v3/pkg/detectors"
	"github.com/trufflesecurity/trufflehog/v3/pkg/pb/detectorspb"
)

type Scanner struct {
	client *http.Client
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	defaultClient = common.SaneHttpClient()
	// Make sure that your group is surrounded in boundary characters such as below to reduce false positives.
	accessKeyPa = regexp.MustCompile(`\b[A-Z0-9]{20}\b`)
	skPa        = regexp.MustCompile(`\b[A-Z0-9a-z]{40}\b`)
)

// Keywords are used for efficiently pre-filtering chunks.
// Use identifiers in the secret preferably, or the provider name.
func (s Scanner) Keywords() []string {
	return []string{"hw", "huawei", "=", "key", "ak", "sk", "cre", "access", "hcloud", ":"}
}

// FromData will find and optionally verify Hwcloud secrets in a given set of bytes.
func (s Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)
	matches := accessKeyPa.FindAllStringSubmatch(dataStr, -1)
	skmatches := skPa.FindAllStringSubmatch(dataStr, -1)

	for _, match := range matches {

		resMatch := strings.TrimSpace(match[0])

		for _, skMatch := range skmatches {

			resSkMatch := strings.TrimSpace(skMatch[0])
			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_CustomRegex,
				Raw:          []byte(resMatch),
				RawV2:        []byte(fmt.Sprintf("ak:%s,sk:%s", resMatch, resSkMatch)),
			}

			if verify {
				client := s.client
				if client == nil {
					client = defaultClient
				}

				isVerified, extraData, verificationErr := verifyMatch(ctx, client, resSkMatch)
				s1.Verified = isVerified
				s1.ExtraData = extraData
				s1.SetVerificationError(verificationErr, resSkMatch)
			}

			results = append(results, s1)
		}

	}
	return results, nil
}

func verifyMatch(ctx context.Context, client *http.Client, token string) (bool, map[string]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://eth-mainnet.g.hwcloud.com/v2/"+token+"/getNFTs/?owner=vitalik.eth", nil)
	if err != nil {
		return false, nil, nil
	}

	res, err := client.Do(req)
	if err != nil {
		return false, nil, err
	}
	defer func() {
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
	}()

	switch res.StatusCode {
	case http.StatusOK:
		// If the endpoint returns useful information, we can return it as a map.
		return true, nil, nil
	case http.StatusUnauthorized:
		// The secret is determinately not verified (nothing to do)
		return false, nil, nil
	default:
		return false, nil, fmt.Errorf("unexpected HTTP response status %d", res.StatusCode)
	}
}

func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_CustomRegex
}

func (s Scanner) Description() string {
	return "Hwcloud is a blockchain development platform that provides a suite of tools and services for building and scaling decentralized applications. Hwcloud API keys can be used to access these services."
}
