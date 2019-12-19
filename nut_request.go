package sqrlua

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"

	ssp "github.com/smw1218/sqrl-ssp"
)

// NutResponse data from nut NutRequest
type NutResponse struct {
	Nut     ssp.Nut
	SQRLURL *url.URL
	// specifc to go sqrl-ssp
	PagNut ssp.Nut
	Can    string
}

type Nutter interface {
	GetNut() (*NutResponse, error)
}

type JavaNutter struct{}

func (j *JavaNutter) GetNut() (*NutResponse, error) {
	log.Printf("running nut request")
	var u = "https://sqrljava.com:20000/sqrlexample/login"
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
		resp.Write(os.Stderr)
		return nil, fmt.Errorf("invalid response code: %v", resp.Status)
	}
	sqrlURL, err := parseSQRLURLFromBody(resp.Body)
	if err != nil {
		return nil, err
	}
	params := sqrlURL.Query()
	nr := &NutResponse{
		Nut:     ssp.Nut(params.Get("nut")),
		SQRLURL: sqrlURL,
	}
	return nr, nil
}

type DotNetNutter struct{}

type DotNetResponse struct {
	URL          string `json:"url"`
	CheckURL     string `json:"checkUrl"`
	CancelUrl    string `json:"cancelUrl"`
	QRCodeBase64 string `json:"qrCodeBase64"`
	RedirectUrl  string `json:"redirectUrl"`
}

func (dnr *DotNetResponse) ParsedURL() (*url.URL, error) {
	return url.Parse(dnr.URL)
}

func (j *DotNetNutter) GetNut() (*NutResponse, error) {
	log.Printf("running nut request")
	var u = "https://www.liamraper.me.uk/login-sqrl?Helper"
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
		resp.Write(os.Stderr)
		return nil, fmt.Errorf("invalid response code: %v", resp.Status)
	}

	dnr := &DotNetResponse{}
	dec := json.NewDecoder(resp.Body)
	err = dec.Decode(&dnr)
	if err != nil {
		return nil, err
	}
	sqrlURL, err := dnr.ParsedURL()
	if err != nil {
		return nil, err
	}
	params := sqrlURL.Query()
	nr := &NutResponse{
		Nut:     ssp.Nut(params.Get("nut")),
		SQRLURL: sqrlURL,
	}
	return nr, nil
}

var sqrlURLRegexp = regexp.MustCompile(`sqrl://[\-0-9A-Za-z._~:/?#[\]@!$&'()*+,;=]+`)

func parseSQRLURLFromBody(body io.Reader) (*url.URL, error) {
	scanner := bufio.NewScanner(body)
	for scanner.Scan() {
		if match := sqrlURLRegexp.FindString(scanner.Text()); match != "" {
			log.Printf("Got match: %v", match)
			u, err := url.Parse(match)
			return u, err
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return nil, fmt.Errorf("SQRL URL Not Found")
}
