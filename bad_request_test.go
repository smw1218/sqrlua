package sqrlua

import (
	"testing"

	ssp "github.com/smw1218/sqrl-ssp"
)

func TestBadNutRequest(t *testing.T) {
	client := &Client{
		Scheme:   scheme,
		Host:     host,
		RootPath: path,
	}

	// broken request with unknown nut
	req := &ssp.CliRequest{}
	cliURL := client.CliURL(ssp.Nut("1234"), "")
	resp, err := client.MakeRawCliRequest(cliURL, req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}

	errors := TIFCompare(ssp.TIFClientFailure|ssp.TIFCommandFailed, resp.TIF)
	if errors != nil {
		t.Errorf("tif e: 0x%x a: 0x%x", 0x80, resp.TIF)
		for _, err := range errors {
			t.Errorf("TIF Fail: %v", err)
		}
	}
}

func TestBadIdsSignature(t *testing.T) {
	client, err := NewClient(scheme, host, path)
	if err != nil {
		t.Fatalf("Failed client gen: %v", err)
	}

	// lazy have the client get a valid nut
	t.Run("A=1", func(t *testing.T) { testValidCmd(t, client, "query", ssp.TIFIPMatched) })

	// broken request with garbage signature
	req := &ssp.CliRequest{
		Client: &ssp.ClientBody{
			Version: []int{1},
			Cmd:     "query",
			Idk:     ssp.Sqrl64.EncodeToString(client.Identity.Idk),
		},
		Ids: "somegarbage",
	}
	resp, err := client.MakeStandardURLRawCliRequest(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}

	errors := TIFCompare(ssp.TIFClientFailure|ssp.TIFCommandFailed, resp.TIF)
	if errors != nil {
		t.Errorf("tif e: 0x%x a: 0x%x", 0x80, resp.TIF)
		for _, err := range errors {
			t.Errorf("TIF Fail: %v", err)
		}
	}
}
