package desec

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strings"

	"github.com/qdm12/ddns-updater/internal/models"
	"github.com/qdm12/ddns-updater/internal/provider/constants"
	"github.com/qdm12/ddns-updater/internal/provider/errors"
	"github.com/qdm12/ddns-updater/internal/provider/headers"
	"github.com/qdm12/ddns-updater/internal/provider/utils"
	"github.com/qdm12/ddns-updater/pkg/publicip/ipversion"
)

type Provider struct {
	domain        string
	host          string
	ipVersion     ipversion.IPVersion
	token         string
	useProviderIP bool
}

func New(data json.RawMessage, domain, host string,
	ipVersion ipversion.IPVersion) (p *Provider, err error) {
	extraSettings := struct {
		Token         string `json:"token"`
		UseProviderIP bool   `json:"provider_ip"`
	}{}
	err = json.Unmarshal(data, &extraSettings)
	if err != nil {
		return nil, err
	}
	p = &Provider{
		domain:        domain,
		host:          host,
		ipVersion:     ipVersion,
		token:         extraSettings.Token,
		useProviderIP: extraSettings.UseProviderIP,
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
	return utils.ToString(p.domain, p.host, constants.DeSEC, p.ipVersion)
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
		Provider:  "<a href=\"https://desec.io/\">deSEC</a>",
		IPVersion: p.ipVersion.String(),
	}
}

func (p *Provider) Update(ctx context.Context, client *http.Client, ip netip.Addr) (newIP netip.Addr, err error) {
	u := url.URL{
		Scheme: "https",
		User:   url.UserPassword(p.BuildDomainName(), p.token),
		Host:   "update.dedyn.io",
		Path:   "/nic/update",
	}
	values := url.Values{}
	values.Set("hostname", utils.BuildURLQueryHostname(p.host, p.domain))
	if !p.useProviderIP {
		values.Set("myip", ip.String())
	}
	u.RawQuery = values.Encode()

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

	b, err := io.ReadAll(response.Body)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("reading response body: %w", err)
	}
	s := string(b)

	switch response.StatusCode {
	case http.StatusOK:
	case http.StatusUnauthorized:
		return netip.Addr{}, fmt.Errorf("%w: %s", errors.ErrAuth, utils.ToSingleLine(s))
	case http.StatusNotFound:
		return netip.Addr{}, fmt.Errorf("%w: %s", errors.ErrHostnameNotExists, utils.ToSingleLine(s))
	default:
		return netip.Addr{}, fmt.Errorf("%w: %d: %s", errors.ErrHTTPStatusNotValid,
			response.StatusCode, utils.ToSingleLine(s))
	}

	switch {
	case strings.HasPrefix(s, constants.Notfqdn):
		return netip.Addr{}, fmt.Errorf("%w", errors.ErrHostnameNotExists)
	case strings.HasPrefix(s, "badrequest"):
		return netip.Addr{}, fmt.Errorf("%w", errors.ErrBadRequest)
	case strings.HasPrefix(s, "good"):
		return ip, nil
	default:
		return netip.Addr{}, fmt.Errorf("%w: %s", errors.ErrUnknownResponse, utils.ToSingleLine(s))
	}
}
