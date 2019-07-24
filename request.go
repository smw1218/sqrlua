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

// Client is a stafeful client to a single SQRL SSP service
type Client struct {
	Scheme             string
	Host               string
	RootPath           string
	Identity           *FakeIdentity
	NutResponse        *NutResponse
	CurrentNut         ssp.Nut
	LastServerResponse string
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
	u.Path += "/cli.sqrl"
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
		_, err := c.MakeNutRequest()
		if err != nil {
			return nil, err
		}
	}

	cliURL := c.CliURL(c.CurrentNut, c.NutResponse.Can)
	c.ApplyStateAndSign(cli)

	return c.MakeRawCliRequest(cliURL, cli)
}

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

// MakeRawCliRequest makes an unmodified request as passed in.
// It does save to c.LastResponse and c.CurrentNut to enable better chaining
func (c *Client) MakeRawCliRequest(cliURL string, cli *ssp.CliRequest) (*ssp.CliResponse, error) {
	log.Printf("Posting to %v", cliURL)
	reqBody := cli.Encode()
	log.Printf("Req Client: %#v", cli.Client)
	log.Printf("Body %v", reqBody)
	resp, err := http.Post(cliURL, "application/x-www-form-urlencoded", strings.NewReader(reqBody))
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
	log.Printf("Resp raw: %v", string(body))
	cliResp, err := ssp.ParseCliResponse(body)
	if err != nil {
		return nil, err
	}
	c.LastServerResponse = string(body)
	c.CurrentNut = cliResp.Nut
	return cliResp, nil
}

// SQRLCliURL returns a SQRL url for the configured server
func (c *Client) SQRLCliURL(nr *NutResponse, includeCan bool) string {
	u := c.baseURL()
	u.Scheme = ssp.SqrlScheme
	u.Path += "/cli.sqrl"
	params := make(url.Values)
	params.Add("nut", string(nr.Nut))
	if includeCan {
		params.Add("can", ssp.Sqrl64.EncodeToString([]byte(nr.Can)))
	}
	u.RawQuery = params.Encode()
	return u.String()
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

// NutResponse data from nut NutRequest
type NutResponse struct {
	Nut    ssp.Nut
	PagNut ssp.Nut
	Can    string
}

// MakeNutRequest make a request for a nut
// sets the response as the NutReponse on the client
// and sets LastServerReponse to the a SQRL URL.
// These can be overridden after the request.
func (c *Client) MakeNutRequest() (*NutResponse, error) {
	u := c.NutURL()
	resp, err := http.Get(u)
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
	c.NutResponse = nr
	c.LastServerResponse = ssp.Sqrl64.EncodeToString([]byte(c.SQRLCliURL(nr, false)))
	c.CurrentNut = nr.Nut
	return nr, nil
}
