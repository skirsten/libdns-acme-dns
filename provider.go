// Package libdnsacmedns implements a DNS record management client compatible
// with the libdns interfaces for acme-dns.
package libdnsacmedns

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"path"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/libdns/libdns"
)

// Provider facilitates DNS record manipulation with acme-dns.
type Provider struct {
	Endpoint  string `json:"endpoint,omitempty"`
	Username  string `json:"username,omitempty"`
	Password  string `json:"password,omitempty"`
	Subdomain string `json:"subdomain,omitempty"`
}

type UpdateBody struct {
	Subdomain string `json:"subdomain"`
	Value     string `json:"txt"`
}

// GetRecords lists all the records in the zone.
func (p *Provider) GetRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	return nil, fmt.Errorf("not implemented")
}

// From https://github.com/joohoi/acme-dns/blob/68bb6ab654b6fb1fe375e08807688c55621513a2/util.go#L60
func sanitizeString(s string) string {
	// URL safe base64 alphabet without padding as defined in ACME
	re, _ := regexp.Compile(`[^A-Za-z\-\_0-9]+`)
	return re.ReplaceAllString(s, "")
}

// From https://github.com/joohoi/acme-dns/blob/68bb6ab654b6fb1fe375e08807688c55621513a2/validation.go#L34
func validTXT(s string) bool {
	sn := sanitizeString(s)
	if utf8.RuneCountInString(s) == 43 && utf8.RuneCountInString(sn) == 43 {
		// 43 chars is the current LE auth key size, but not limited / defined by ACME
		return true
	}
	return false
}

func (p *Provider) updateRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	if len(records) != 1 {
		return nil, fmt.Errorf("not implemented")
	}

	rec := records[0]

	if rec.Type != "TXT" || !strings.HasPrefix(rec.Name, "_acme_challenge") || !validTXT(rec.Value) {
		return nil, fmt.Errorf("not implemented")
	}

	body, _ := json.Marshal(UpdateBody{
		Subdomain: p.Subdomain,
		Value:     rec.Value,
	})

	request, err := http.NewRequestWithContext(ctx, "POST", path.Join(p.Endpoint, "update"), bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}

	request.Header.Set("content-type", "application/json")
	request.Header.Set("x-api-user", p.Username)
	request.Header.Set("x-api-key", p.Password)

	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return nil, err
	}

	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf(
			"acme-dns update failed: POST %s, subdomain: %s, value: %s  %s",
			response.Request.RequestURI, p.Subdomain, rec.Value, response.Status,
		)
	}

	return records, nil
}

// AppendRecords adds records to the zone. It returns the records that were added.
func (p *Provider) AppendRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	return p.updateRecords(ctx, zone, records)
}

// SetRecords sets the records in the zone, either by updating existing records or creating new ones.
// It returns the updated records.
func (p *Provider) SetRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	return p.updateRecords(ctx, zone, records)
}

// DeleteRecords deletes the records from the zone. It returns the records that were deleted.
func (p *Provider) DeleteRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	// delete flow is not implemented by acme-dns yet: https://github.com/joohoi/acme-dns/search?q=delete&type=issues
	return nil, nil
}

// Interface guards
var (
	_ libdns.RecordGetter   = (*Provider)(nil)
	_ libdns.RecordAppender = (*Provider)(nil)
	_ libdns.RecordSetter   = (*Provider)(nil)
	_ libdns.RecordDeleter  = (*Provider)(nil)
)
