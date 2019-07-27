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

	var expectedTIF uint32 = ssp.TIFClientFailure | ssp.TIFCommandFailed
	errors := TIFCompare(expectedTIF, resp.TIF)
	if errors != nil {
		t.Errorf("tif e: 0x%x a: 0x%x", expectedTIF, resp.TIF)
		for _, err := range errors {
			t.Errorf("TIF Fail: %v", err)
		}
	}
}

func TestQueryIdentDisableEnableNoURS(t *testing.T) {
	client, err := NewClient(scheme, host, path)
	if err != nil {
		t.Fatalf("Failed client gen: %v", err)
	}

	t.Run("A=1", func(t *testing.T) { testValidCmd(t, client, "query", ssp.TIFIPMatched) })

	t.Run("A=2", func(t *testing.T) { testValidCmd(t, client, "ident", ssp.TIFIPMatched) })

	// disable
	t.Run("A=3", func(t *testing.T) {
		testValidCmd(t, client, "disable", ssp.TIFIPMatched|ssp.TIFIDMatch|ssp.TIFSQRLDisabled)
	})

	// broken request with garbage signature
	req := &ssp.CliRequest{
		Client: &ssp.ClientBody{
			Version: []int{1},
			Cmd:     "enable",
		},
	}
	client.ApplyStateAndSign(req)
	// mess up urs
	req.Urs = "somegarbage"

	resp, err := client.MakeStandardURLRawCliRequest(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}

	var expectedTIF uint32 = ssp.TIFIPMatched | ssp.TIFIDMatch | ssp.TIFClientFailure | ssp.TIFCommandFailed | ssp.TIFSQRLDisabled
	errors := TIFCompare(expectedTIF, resp.TIF)
	if errors != nil {
		t.Errorf("tif e: 0x%x a: 0x%x", expectedTIF, resp.TIF)
		for _, err := range errors {
			t.Errorf("TIF Fail: %v", err)
		}
	}

	t.Run("A=4", func(t *testing.T) { testValidCmd(t, client, "enable", ssp.TIFIPMatched|ssp.TIFIDMatch) })
}
