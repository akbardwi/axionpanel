package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"regexp"
	"strings"
	"time"

	"axionpanel/internal/nginxsite"
)

// StaticSitesBackend is the startup-selected, journal-backed static-site
// adapter. nginxsite.Manager satisfies it directly; there is no second model.
type StaticSitesBackend interface {
	Plan(domain string) (nginxsite.Plan, error)
	Apply(ctx context.Context, operationID, domain string) (nginxsite.Result, error)
	Remove(ctx context.Context, operationID, domain string) (nginxsite.Result, error)
	Status(ctx context.Context, domain string) (nginxsite.Result, error)
}

// RegisterStaticSites is opt-in: RegisterBuiltins never calls it, and every
// operation keeps the dedicated StaticSites permission, so the dedicated host
// policy flag is required rather than root_files, a service grant, or the peer
// socket identity.
func RegisterStaticSites(r *Registry, backend StaticSitesBackend) {
	if r == nil || backend == nil {
		panic("agent: static sites require a registry and backend")
	}
	for _, action := range []string{"plan", "apply", "remove", "status"} {
		action := action
		mutation := action == "apply" || action == "remove"
		r.Register("site."+action, func(ctx context.Context, raw Params, _ RequestMeta) (any, error) {
			in, err := decodeSiteParams(raw, mutation)
			if err != nil {
				return nil, err
			}
			if mutation {
				if err := validateSiteOperationID(in.OperationID); err != nil {
					return nil, err
				}
			} else if in.OperationID != "" {
				return nil, invalidParams(map[string]string{"operation_id": "not accepted"})
			}
			if action != "plan" {
				if err := siteDeadline(ctx); err != nil {
					return nil, err
				}
			}
			switch action {
			case "plan":
				plan, err := backend.Plan(in.Domain)
				return plan, siteError(err)
			case "apply":
				res, err := backend.Apply(ctx, in.OperationID, in.Domain)
				return res, siteError(err)
			case "remove":
				res, err := backend.Remove(ctx, in.OperationID, in.Domain)
				return res, siteError(err)
			default:
				res, err := backend.Status(ctx, in.Domain)
				return res, siteError(err)
			}
		}, StaticSites)
	}
}

type siteParams struct {
	Domain      string `json:"domain"`
	OperationID string `json:"operation_id"`
}

// decodeSiteParams accepts exactly {"domain"} for reads and {"domain",
// "operation_id"} for mutations. Paths, listen addresses, extra or duplicate
// keys are rejected before any adapter call.
func decodeSiteParams(raw Params, mutation bool) (siteParams, error) {
	var out siteParams
	var fields map[string]json.RawMessage
	if err := decodeParams(raw, &fields); err != nil {
		return out, err
	}
	if len(bytes.TrimSpace(raw)) > 0 {
		if err := rejectDuplicateJSONKeys(raw); err != nil {
			return out, err
		}
	}
	if len(fields) > 0 {
		if firstUnknownSiteKey(fields, mutation) != "" {
			return out, invalidParams(map[string]string{"unknown_key": "present"})
		}
	}
	if err := decodeParams(raw, &out); err != nil {
		return out, err
	}
	if out.Domain == "" {
		return out, invalidParams(map[string]string{"domain": "required"})
	}
	if err := validateSiteDomain(out.Domain); err != nil {
		return out, err
	}
	return out, nil
}

// firstUnknownSiteKey reports whether any key outside the per-action allow-list
// is present. It returns only the fact that one exists; the key text (which
// may be an arbitrary host path) is never echoed into the response.
func firstUnknownSiteKey(fields map[string]json.RawMessage, mutation bool) string {
	for key := range fields {
		if key == "domain" || (mutation && key == "operation_id") {
			continue
		}
		return key
	}
	return ""
}

func siteDeadline(ctx context.Context) error {
	dl, ok := ctx.Deadline()
	if !ok || time.Until(dl) <= 0 {
		return newOpError(ErrInvalidParams, "static site operation requires a live deadline", nil)
	}
	return nil
}

func validateSiteOperationID(id string) error {
	bad := invalidParams(map[string]string{"operation_id": "must be 32 lowercase hex characters"})
	if len(id) != 32 {
		return bad
	}
	for _, r := range id {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return bad
		}
	}
	return nil
}

var siteDomainLabel = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// validateSiteDomain rejects anything that cannot be a plain lowercase DNS
// hostname. The adapter revalidates; this edge check keeps arbitrary paths and
// case/IDN tricks out of the request path entirely.
func validateSiteDomain(d string) error {
	bad := invalidParams(map[string]string{"domain": "must be a lowercase DNS hostname"})
	if d == "" || len(d) > 253 || net.ParseIP(d) != nil || strings.HasSuffix(d, ".") {
		return bad
	}
	labels := strings.Split(d, ".")
	if len(labels) < 2 {
		return bad
	}
	for _, l := range labels {
		if !siteDomainLabel.MatchString(l) {
			return bad
		}
	}
	if strings.Trim(labels[len(labels)-1], "0123456789") == "" {
		return bad
	}
	return nil
}

// siteError maps adapter failures onto protocol codes with fixed messages: raw
// nginx output, host paths and journal text never reach the panel.
func siteError(err error) error {
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, nginxsite.ErrInvalidDomain), errors.Is(err, nginxsite.ErrInvalidOperationID):
		return invalidParams(map[string]string{"domain": "invalid domain or operation id"})
	case errors.Is(err, nginxsite.ErrDeadlineRequired), errors.Is(err, context.DeadlineExceeded):
		return newOpError(ErrInvalidParams, "static site operation deadline expired", nil)
	case errors.Is(err, nginxsite.ErrRetainedContent):
		return newOpError(ErrConflict, "retained site content blocks this operation", nil)
	case errors.Is(err, nginxsite.ErrOperationConflict):
		return newOpError(ErrConflict, "operation id was reused with different input", nil)
	case errors.Is(err, nginxsite.ErrInterruptedOp), errors.Is(err, nginxsite.ErrLocked):
		return newOpError(ErrConflict, "site operation is not in a safe state", nil)
	case errors.Is(err, nginxsite.ErrPreexistingConfig):
		return newOpError(ErrPreexistingConfig, "nginx configuration is not in the expected baseline", nil)
	case errors.Is(err, nginxsite.ErrConfigTestFailed):
		return newOpError(ErrConfigTestFailed, "nginx configuration test failed", nil)
	case errors.Is(err, nginxsite.ErrUnsafePath):
		return newOpError(ErrInternal, "static site path validation failed", nil)
	}
	return newOpError(ErrInternal, "static site operation failed", nil)
}
