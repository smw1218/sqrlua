package sqrlua

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/crypto/ed25519"

	ssp "github.com/smw1218/sqrl-ssp"
)

var UseJava = false
var UseDotNet = false

// Client is a stafeful client to a single SQRL SSP service
type Client struct {
	Scheme             string
	Host               string
	RootPath           string
	Identity           *FakeIdentity
	NutResponse        *NutResponse
	Qry                string
	CurrentNut         ssp.Nut
	LastServerResponse string
	Nutter             Nutter
}

// NewClient creates a new client with a generated FakeIdentity
func NewClient(scheme, host, rootPath string) (*Client, error) {
	fi, err := NewFakeIdentity()
	if err != nil {
		return nil, fmt.Errorf("failed identity gen: %v", err)
	}
	client := &Client{
		Scheme:   scheme,
		Host:     host,
		RootPath: rootPath,
		Identity: fi,
	}

	if UseJava {
		client.Nutter = &JavaNutter{}
	} else if UseDotNet {
		client.Nutter = &DotNetNutter{}
	} else {
		// default to self for the Nutter
		client.Nutter = client
	}
	return client, nil
}

// CliURL get a url for a cli request
func (c *Client) CliURL(nut ssp.Nut, can string) string {
	params := make(url.Values)
	if nut != "" {
		params.Add("nut", string(nut))
	}
	if can != "" {
		params.Add("can", can)
	}
	u := c.baseURL()
	u.Path = c.Qry
	if len(params) > 0 {
		u.RawQuery = params.Encode()
	}
	return u.String()
}

func (c *Client) NutURL() string {
	u := c.baseURL()
	u.Path += "/nut.sqrl"
	return u.String()
}

func (c *Client) baseURL() *url.URL {
	u := &url.URL{
		Scheme: c.Scheme,
		Host:   c.Host,
		Path:   c.RootPath,
	}
	return u
}

// MakeCliRequest tries to make a valid cli request filling in the internal state as we go
func (c *Client) MakeCliRequest(cli *ssp.CliRequest) (*ssp.CliResponse, error) {
	if c.CurrentNut == "" {
		nr, err := c.Nutter.GetNut()
		if err != nil {
			return nil, err
		}
		c.NutResponse = nr
		c.LastServerResponse = ssp.Sqrl64.EncodeToString([]byte(nr.SQRLURL.String()))
		c.Qry = nr.SQRLURL.Path
		c.CurrentNut = nr.Nut
	}

	cliURL := c.CliURL(c.CurrentNut, c.NutResponse.Can)
	c.ApplyStateAndSign(cli)

	return c.MakeRawCliRequest(cliURL, cli)
}

// ApplyStateAndSign applies all the correct state from the client and signs where necessary
func (c *Client) ApplyStateAndSign(cli *ssp.CliRequest) {
	cli.Server = c.LastServerResponse
	if cli.Client.Cmd == "ident" {
		cli.Client.Vuk = ssp.Sqrl64.EncodeToString(c.Identity.Vuk)
		cli.Client.Suk = ssp.Sqrl64.EncodeToString(c.Identity.Suk)
	}
	if cli.Client.Cmd == "enable" || cli.Client.Cmd == "remove" {
		c.Identity.SignIdkAndURS(cli)
	} else {
		c.Identity.SignIdk(cli)
	}
}

// MakeStandardURLRawCliRequest makes a raw request with the standard URL
func (c *Client) MakeStandardURLRawCliRequest(cli *ssp.CliRequest) (*ssp.CliResponse, error) {
	cliURL := c.CliURL(c.CurrentNut, c.NutResponse.Can)
	return c.MakeRawCliRequest(cliURL, cli)
}

// MakeRawCliRequest makes an unmodified request as passed in.
// It does save to c.LastResponse and c.CurrentNut to enable better chaining
func (c *Client) MakeRawCliRequest(cliURL string, cli *ssp.CliRequest) (*ssp.CliResponse, error) {
	reqBody := cli.Encode()
	cmd := "none"
	if cli != nil && cli.Client != nil {
		cmd = cli.Client.Cmd
	}
	log.Printf("Posting %v to: %v", cmd, cliURL)
	log.Printf("Body: %v", reqBody)
	req, err := http.NewRequest(http.MethodPost, cliURL, strings.NewReader(reqBody))
	if err != nil {
		return nil, err
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		return nil, fmt.Errorf("error posting request: %v", err)
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading response body: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("invalid response code: %v", resp.Status)
	}
	log.Printf("Response: %v", string(body))
	cliResp, err := ssp.ParseCliResponse(body)
	if err != nil {
		return nil, err
	}
	c.LastServerResponse = string(body)
	c.CurrentNut = cliResp.Nut
	return cliResp, nil
}

// SQRLCliURL returns a SQRL url for the configured SSP server
func (c *Client) SQRLCliURL(nr *NutResponse, includeCan bool) *url.URL {
	u := c.baseURL()
	u.Scheme = ssp.SqrlScheme
	u.Path += "/cli.sqrl"
	params := make(url.Values)
	params.Add("nut", string(nr.Nut))
	if includeCan {
		params.Add("can", ssp.Sqrl64.EncodeToString([]byte(nr.Can)))
	}
	u.RawQuery = params.Encode()
	return u
}

// FakeIdentity holds keys to allow for test requests to a SQRL server
type FakeIdentity struct {
	IdkPrivate ed25519.PrivateKey
	Idk        ed25519.PublicKey
	VukPrivate ed25519.PrivateKey
	Vuk        ed25519.PublicKey
	Suk        ed25519.PublicKey
}

// NewFakeIdentity create a fake identity to make test requests
func NewFakeIdentity() (*FakeIdentity, error) {
	fi := &FakeIdentity{}
	var err error
	fi.Idk, fi.IdkPrivate, err = ed25519.GenerateKey(nil)
	if err != nil {
		return nil, err
	}
	fi.Vuk, fi.VukPrivate, err = ed25519.GenerateKey(nil)
	if err != nil {
		return nil, err
	}

	// this is fake since we're not managing an actual master identity
	fi.Suk, _, err = ed25519.GenerateKey(nil)
	if err != nil {
		return nil, err
	}

	return fi, nil
}

// SignIdk signs and sets the idk and ids on the CliRequest
func (fi *FakeIdentity) SignIdk(req *ssp.CliRequest) {
	req.Client.Idk = ssp.Sqrl64.EncodeToString(fi.Idk)
	fi.signIdk(req)
}

// SignIdkAndURS signs and sets the idk, ids, vuk and urs on the CliRequest
func (fi *FakeIdentity) SignIdkAndURS(req *ssp.CliRequest) {
	req.Client.Idk = ssp.Sqrl64.EncodeToString(fi.Idk)
	req.Client.Vuk = ssp.Sqrl64.EncodeToString(fi.Vuk)
	fi.signIdk(req)
	fi.signUrs(req)
}

func (fi *FakeIdentity) signIdk(req *ssp.CliRequest) {
	req.Ids = ssp.Sqrl64.EncodeToString(ed25519.Sign(fi.IdkPrivate, req.SigningString()))
}

func (fi *FakeIdentity) signUrs(req *ssp.CliRequest) {
	req.Urs = ssp.Sqrl64.EncodeToString(ed25519.Sign(fi.VukPrivate, req.SigningString()))
}

func (c *Client) GetNut() (*NutResponse, error) {
	return c.MakeNutRequest()
}

// MakeNutRequest make a request for a nut
// sets the response as the NutReponse on the client
// and sets LastServerReponse to the a SQRL URL.
// These can be overridden after the request.
func (c *Client) MakeNutRequest() (*NutResponse, error) {
	u := c.NutURL()
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("invalid response code: %v", resp.Status)
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	params, err := url.ParseQuery(string(body))
	if err != nil {
		return nil, fmt.Errorf("couldn't parse url encoded body: %v", err)
	}
	nr := &NutResponse{
		Nut:    ssp.Nut(params.Get("nut")),
		PagNut: ssp.Nut(params.Get("pag")),
		Can:    params.Get("can"),
	}
	nr.SQRLURL = c.SQRLCliURL(nr, false)
	return nr, nil
}
