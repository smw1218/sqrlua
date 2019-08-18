package sqrlua

import (
	"flag"
	"os"
	"testing"

	ssp "github.com/smw1218/sqrl-ssp"
)

// var scheme = "https"
// var host = "sqrl.grc.com"

var scheme = "http"
var host = "localhost:8000"
var path = ""
var java bool

func TestMain(m *testing.M) {
	flag.StringVar(&scheme, "scheme", "http", "url scheme for the host")
	flag.StringVar(&host, "host", "localhost:8000", "host to execute the tests against")
	flag.StringVar(&path, "path", "", "path where the SQRL API is rooted if not /")
	flag.BoolVar(&java, "java", false, "make requests compatible with the sqrljava.com")
	flag.Parse()
	UseJava = java
	os.Exit(m.Run())
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
		t.Errorf("TIF expected: 0x%x actual: 0x%x", expectedTIF, resp.TIF)
		for _, err := range errors {
			t.Errorf("TIF Fail: %v", err)
		}
	}
	return resp
}

func testRawReq(t *testing.T, client *Client, req *ssp.CliRequest, expectedTIF uint32) *ssp.CliResponse {
	resp, err := client.MakeStandardURLRawCliRequest(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}

	// should be unknown identity so only ip matched
	errors := TIFCompare(expectedTIF, resp.TIF)
	if errors != nil {
		t.Errorf("TIF expected: 0x%x actual: 0x%x", expectedTIF, resp.TIF)
		for _, err := range errors {
			t.Errorf("TIF Fail: %v", err)
		}
	}
	return resp
}

func TestGoodQueryRequest(t *testing.T) {
	client, err := NewClient(scheme, host, path)
	if err != nil {
		t.Fatalf("Failed client gen: %v", err)
	}

	t.Run("A=1", func(t *testing.T) { testValidCmd(t, client, "query", ssp.TIFIPMatched) })
	// again with same identity but next nut
	t.Run("A=2", func(t *testing.T) { testValidCmd(t, client, "query", ssp.TIFIPMatched) })

}

func TestGoodQueryIdent(t *testing.T) {
	fi, err := NewFakeIdentity()
	if err != nil {
		t.Fatalf("Failed key gen: %v", err)
	}
	client, err := NewClient(scheme, host, path)
	if err != nil {
		t.Fatalf("Failed client gen: %v", err)
	}
	client.Identity = fi
	t.Run("A=1", func(t *testing.T) { testValidCmd(t, client, "query", ssp.TIFIPMatched) })
	// again with same identity but next nut
	t.Run("A=2", func(t *testing.T) { testValidCmd(t, client, "ident", ssp.TIFIPMatched|ssp.TIFIDMatch) })
}

func TestGoodQueryIdentQuery(t *testing.T) {
	client, err := NewClient(scheme, host, path)
	if err != nil {
		t.Fatalf("Failed client gen: %v", err)
	}

	t.Run("A=1", func(t *testing.T) { testValidCmd(t, client, "query", ssp.TIFIPMatched) })

	t.Run("A=2", func(t *testing.T) { testValidCmd(t, client, "ident", ssp.TIFIPMatched|ssp.TIFIDMatch) })

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

func TestGoodQueryIdentDisableEnable(t *testing.T) {
	client, err := NewClient(scheme, host, path)
	if err != nil {
		t.Fatalf("Failed client gen: %v", err)
	}

	t.Run("A=1", func(t *testing.T) { testValidCmd(t, client, "query", ssp.TIFIPMatched) })

	t.Run("A=2", func(t *testing.T) { testValidCmd(t, client, "ident", ssp.TIFIPMatched|ssp.TIFIDMatch) })

	// disable
	t.Run("A=3", func(t *testing.T) {
		testValidCmd(t, client, "disable", ssp.TIFIPMatched|ssp.TIFIDMatch|ssp.TIFSQRLDisabled)
	})

	t.Run("A=4", func(t *testing.T) { testValidCmd(t, client, "enable", ssp.TIFIPMatched|ssp.TIFIDMatch) })
}

func TestGoodQueryIdentRemove(t *testing.T) {
	client, err := NewClient(scheme, host, path)
	if err != nil {
		t.Fatalf("Failed client gen: %v", err)
	}

	t.Run("A=1", func(t *testing.T) { testValidCmd(t, client, "query", ssp.TIFIPMatched) })

	t.Run("A=2", func(t *testing.T) { testValidCmd(t, client, "ident", ssp.TIFIPMatched|ssp.TIFIDMatch) })

	// remove
	t.Run("A=3", func(t *testing.T) {
		testValidCmd(t, client, "remove", ssp.TIFIPMatched)
	})

	t.Run("A=4", func(t *testing.T) { testValidCmd(t, client, "query", ssp.TIFIPMatched) })
}
