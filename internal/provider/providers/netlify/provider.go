package netlify

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"

	"github.com/qdm12/ddns-updater/internal/models"
	"github.com/qdm12/ddns-updater/internal/provider/errors"
	"github.com/qdm12/ddns-updater/internal/provider/headers"
	"github.com/qdm12/ddns-updater/internal/provider/utils"
	"github.com/qdm12/ddns-updater/pkg/publicip/ipversion"
)

var (
	apiHost = "api.netlify.com"
)

type Provider struct {
	domain    string
	host      string
	ipVersion ipversion.IPVersion
	token     string
	id        string
}

func New(data json.RawMessage, domain, host string,
	ipVersion ipversion.IPVersion) (p *Provider, err error) {
	extraSettings := struct {
		Token string `json:"token"`
	}{}
	err = json.Unmarshal(data, &extraSettings)
	if err != nil {
		return nil, err
	}
	p = &Provider{
		domain:    domain,
		host:      host,
		ipVersion: ipVersion,
		token:     extraSettings.Token,
	}
	err = p.isValid()
	if err != nil {
		return nil, err
	}
	return p, nil
}

func (p *Provider) isValid() error {
	switch {
	case p.token == "":
		return fmt.Errorf("%w", errors.ErrTokenNotSet)
	case p.host == "*":
		return fmt.Errorf("%w", errors.ErrHostWildcard)
	}
	return nil
}

func (p *Provider) String() string {
	return fmt.Sprintf("[domain: %s | host: %s | provider: Netlify]", p.domain, p.host)
}

func (p *Provider) Domain() string {
	return p.domain
}

func (p *Provider) Host() string {
	return p.host
}

func (p *Provider) IPVersion() ipversion.IPVersion {
	return p.ipVersion
}

func (p *Provider) Proxied() bool {
	return false
}

func (p *Provider) BuildDomainName() string {
	return utils.BuildDomainName(p.host, p.domain)
}

func (p *Provider) HTML() models.HTMLRow {
	return models.HTMLRow{
		Domain:    fmt.Sprintf("<a href=\"http://%s\">%s</a>", p.BuildDomainName(), p.BuildDomainName()),
		Host:      p.Host(),
		Provider:  "<a href=\"https://app.netlify.com/\">Netlify</a>",
		IPVersion: p.ipVersion.String(),
	}
}

func (p *Provider) Update(ctx context.Context, client *http.Client, ip netip.Addr) (newIP netip.Addr, err error) {
	// isIPv4 := ip.Is4()
	host := "api.netlify.com"

	u := url.URL{
		Scheme: "https",
		Host:   host,
		Path:   "/api/v1/dns_zones",
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("creating http request: %w", err)
	}
	headers.SetUserAgent(request)

	response, err := client.Do(request)
	if err != nil {
		return netip.Addr{}, err
	}
	defer response.Body.Close()

	if response.StatusCode == http.StatusOK {
		return ip, nil
	}
	return netip.Addr{}, fmt.Errorf("%w: %d: %s",
		errors.ErrHTTPStatusNotValid, response.StatusCode, utils.BodyToSingleLine(response.Body))
}

func (p *Provider) getId(ctx context.Context, client *http.Client) error {
	zones := []struct {
		Id   string `json:"id"`
		Name string `json:"name"`
	}{}

	u := url.URL{
		Scheme: "https",
		Host:   p.host,
		Path:   "/api/v1/dns_zones",
	}

	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	request.Header.Set("Authorization", fmt.Sprintf("Bearer %s", p.token))
	response, err := client.Do(request)
	if err != nil {
		return err
	}

	defer response.Body.Close()

	b, err := io.ReadAll(response.Body)
	if err != nil {
		return fmt.Errorf("reading response body: %w", err)
	}

	json.Unmarshal(b, &zones)
	for _, zone := range zones {
		if zone.Name == p.domain {
			p.id = zone.Id
			return nil
		}
	}
	return fmt.Errorf("domain not found")
}
