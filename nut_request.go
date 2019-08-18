package sqrlua

import (
	"bufio"
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
	sqrlURL, err := j.parseSQRLURLFromBody(resp.Body)
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

func (j *JavaNutter) parseSQRLURLFromBody(body io.Reader) (*url.URL, error) {
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
