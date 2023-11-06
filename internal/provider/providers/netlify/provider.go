package netlify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"

	"github.com/qdm12/ddns-updater/internal/models"
	"github.com/qdm12/ddns-updater/internal/provider/errors"
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
	ip        netip.Addr
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
	p.ip = ip

	err = p.getZoneID(ctx, client)
	if err != nil {
		return netip.Addr{}, err
	}

	aRecordID, err := p.checkArecord(ctx, client)
	if err != nil {
		return netip.Addr{}, err
	}

	if aRecordID != "" {
		err = p.deleteArecord(ctx, client, aRecordID)
		if err != nil {
			return netip.Addr{}, err
		}
	}

	err = p.createArecord(ctx, client, ip)
	if err != nil {
		return netip.Addr{}, err
	}

	return ip, nil
}

func (p *Provider) getZoneID(ctx context.Context, client *http.Client) error {
	zones := []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}{}

	u := url.URL{
		Scheme: "https",
		Host:   apiHost,
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

	err = json.Unmarshal(b, &zones)
	if err != nil {
		return fmt.Errorf("unmarshalling response body: %w", err)
	}

	for _, zone := range zones {
		if zone.Name == p.domain {
			p.id = zone.ID
			return nil
		}
	}
	return fmt.Errorf("zone not found")
}

func (p *Provider) checkArecord(ctx context.Context, client *http.Client) (string, error) {
	records := []struct {
		ID       string `json:"id"`
		Type     string `json:"type"`
		HostName string `json:"hostname"`
	}{}

	u := url.URL{
		Scheme: "https",
		Host:   p.host,
		Path:   fmt.Sprintf("/api/v1/dns_zones/%s/dns_records", p.id),
	}

	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	request.Header.Set("Authorization", fmt.Sprintf("Bearer %s", p.token))
	response, err := client.Do(request)
	if err != nil {
		return "", err
	}

	defer response.Body.Close()

	b, err := io.ReadAll(response.Body)
	if err != nil {
		return "", fmt.Errorf("reading response body: %w", err)
	}

	err = json.Unmarshal(b, &records)
	if err != nil {
		return "", fmt.Errorf("unmarshalling response body: %w", err)
	}

	recordType := "A"
	if p.ipVersion == ipversion.IP6 {
		recordType = "AAAA"
	}

	for _, record := range records {
		if record.Type == recordType && record.HostName == p.host {
			return record.ID, nil
		}
	}
	return "", nil
}

func (p *Provider) deleteArecord(ctx context.Context, client *http.Client, recordID string) error {

	u := url.URL{
		Scheme: "https",
		Host:   apiHost,
		Path:   fmt.Sprintf("/api/v1/dns_zones/%s/dns_records/%s", p.id, recordID),
	}

	request, _ := http.NewRequestWithContext(ctx, http.MethodDelete, u.String(), nil)
	request.Header.Set("Authorization", fmt.Sprintf("Bearer %s", p.token))
	response, err := client.Do(request)
	if err != nil {
		return err
	}

	defer response.Body.Close()

	if response.StatusCode == http.StatusNoContent {
		return nil
	}

	return fmt.Errorf("delete A record failed. Https status not 204: %d", response.StatusCode)
}

func (p *Provider) createArecord(ctx context.Context, client *http.Client, ip netip.Addr) error {
	recordType := "A"
	if p.ipVersion == ipversion.IP6 {
		recordType = "AAAA"
	}

	requestBody := struct {
		Type     string `json:"type"`
		Hostname string `json:"hostname"`
		Value    string `json:"value"`
	}{
		Type:     recordType,
		Hostname: apiHost,
		Value:    ip.String(),
	}

	u := url.URL{
		Scheme: "https",
		Host:   p.host,
		Path:   fmt.Sprintf("/api/v1/dns_zones/%s/dns_records", p.id),
	}

	jsonData, err := json.Marshal(requestBody)
	if err != nil {
		return fmt.Errorf("error serializiong request body: %w", err)
	}

	request, _ := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewBuffer(jsonData))
	request.Header.Set("Authorization", fmt.Sprintf("Bearer %s", p.token))
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("error creating A record: %w", err)
	}

	defer response.Body.Close()

	if response.StatusCode == http.StatusCreated {
		return nil
	}

	return fmt.Errorf("create A record failed. Https status not 201: %d", response.StatusCode)
}
