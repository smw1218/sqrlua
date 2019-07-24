package sqrlua

import (
	"testing"

	ssp "github.com/smw1218/sqrl-ssp"
)

var scheme = "https"
var host = "sqrl.grc.com"

// var scheme = "http"
// var host = "localhost:8000"
var path = ""

func TestBadRequest(t *testing.T) {
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

	errors := TIFCompare(ssp.TIFClientFailure, resp.TIF)
	if errors != nil {
		t.Errorf("tif e: 0x%x a: 0x%x", 0x80, resp.TIF)
		for _, err := range errors {
			t.Errorf("TIF Fail: %v", err)
		}
	}
}

func TestQueryRequest(t *testing.T) {
	fi, err := NewFakeIdentity()
	if err != nil {
		t.Fatalf("Failed key gen: %v", err)
	}
	client := &Client{
		Scheme:   scheme,
		Host:     host,
		RootPath: path,
		Identity: fi,
	}
	t.Run("A=1", func(t *testing.T) { testValidCmd(t, client, "query", ssp.TIFIPMatched) })
	// again with same identity but next nut
	t.Run("A=2", func(t *testing.T) { testValidCmd(t, client, "query", ssp.TIFIPMatched) })

}

func testValidCmd(t *testing.T, client *Client, cmd string, expectedTIF uint32) *ssp.CliResponse {
	// broken request with unknown nut
	req := &ssp.CliRequest{
		Client: &ssp.ClientBody{
			Version: []int{1},
			Cmd:     cmd,
		},
	}

	return testValidReq(t, client, req, expectedTIF)
}

func testValidReq(t *testing.T, client *Client, req *ssp.CliRequest, expectedTIF uint32) *ssp.CliResponse {
	resp, err := client.MakeCliRequest(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}

	// should be unknown identity so only ip matched
	errors := TIFCompare(expectedTIF, resp.TIF)
	if errors != nil {
		t.Errorf("tif e: 0x%x a: 0x%x", expectedTIF, resp.TIF)
		for _, err := range errors {
			t.Errorf("TIF Fail: %v", err)
		}
	}
	return resp
}

func TestQueryIdent(t *testing.T) {
	fi, err := NewFakeIdentity()
	if err != nil {
		t.Fatalf("Failed key gen: %v", err)
	}
	client := &Client{
		Scheme:   scheme,
		Host:     host,
		RootPath: path,
		Identity: fi,
	}
	t.Run("A=1", func(t *testing.T) { testValidCmd(t, client, "query", ssp.TIFIPMatched) })
	// again with same identity but next nut
	t.Run("A=2", func(t *testing.T) { testValidCmd(t, client, "ident", ssp.TIFIPMatched) })
}

func TestQueryIdentQuery(t *testing.T) {
	fi, err := NewFakeIdentity()
	if err != nil {
		t.Fatalf("Failed key gen: %v", err)
	}
	client := &Client{
		Scheme:   scheme,
		Host:     host,
		RootPath: path,
		Identity: fi,
	}
	t.Run("A=1", func(t *testing.T) { testValidCmd(t, client, "query", ssp.TIFIPMatched) })

	t.Run("A=2", func(t *testing.T) { testValidCmd(t, client, "ident", ssp.TIFIPMatched) })

	// should be recognized
	req := &ssp.CliRequest{
		Client: &ssp.ClientBody{
			Version: []int{1},
			Cmd:     "query",
			Opt:     map[string]bool{"suk": true},
		},
	}
	var resp *ssp.CliResponse
	t.Run("A=3", func(t *testing.T) { resp = testValidReq(t, client, req, ssp.TIFIPMatched|ssp.TIFIDMatch) })
	if resp.Suk != ssp.Sqrl64.EncodeToString(client.Identity.Suk) {
		t.Errorf("Suk incorrect from server e: %v a: %v", client.Identity.Suk, resp.Suk)
	}
}

func TestQueryIdentDisableEnable(t *testing.T) {
	fi, err := NewFakeIdentity()
	if err != nil {
		t.Fatalf("Failed key gen: %v", err)
	}
	client := &Client{
		Scheme:   scheme,
		Host:     host,
		RootPath: path,
		Identity: fi,
	}
	t.Run("A=1", func(t *testing.T) { testValidCmd(t, client, "query", ssp.TIFIPMatched) })

	t.Run("A=2", func(t *testing.T) { testValidCmd(t, client, "ident", ssp.TIFIPMatched) })

	// disable
	t.Run("A=3", func(t *testing.T) {
		testValidCmd(t, client, "disable", ssp.TIFIPMatched|ssp.TIFIDMatch|ssp.TIFSQRLDisabled)
	})

	t.Run("A=4", func(t *testing.T) { testValidCmd(t, client, "enable", ssp.TIFIPMatched|ssp.TIFIDMatch) })
}

func TestQueryIdentRemove(t *testing.T) {
	fi, err := NewFakeIdentity()
	if err != nil {
		t.Fatalf("Failed key gen: %v", err)
	}
	client := &Client{
		Scheme:   scheme,
		Host:     host,
		RootPath: path,
		Identity: fi,
	}
	t.Run("A=1", func(t *testing.T) { testValidCmd(t, client, "query", ssp.TIFIPMatched) })

	t.Run("A=2", func(t *testing.T) { testValidCmd(t, client, "ident", ssp.TIFIPMatched) })

	// remove
	t.Run("A=3", func(t *testing.T) {
		testValidCmd(t, client, "remove", ssp.TIFIPMatched|ssp.TIFIDMatch)
	})

	t.Run("A=4", func(t *testing.T) { testValidCmd(t, client, "query", ssp.TIFIPMatched) })
}
