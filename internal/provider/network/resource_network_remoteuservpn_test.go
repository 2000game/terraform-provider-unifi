package network

import (
	"strings"
	"testing"

	"github.com/hashicorp/go-cty/cty"
)

// serverRaw builds a raw config for a remote-user-vpn network. Attributes are
// passed as a map so a case can omit one entirely -- which is the distinction
// these rules turn on, and is not the same as passing a null.
func serverRaw(attrs map[string]cty.Value) cty.Value {
	base := map[string]cty.Value{
		"purpose":            cty.StringVal("remote-user-vpn"),
		"vpn_type":           cty.StringVal("wireguard-server"),
		"subnet":             cty.StringVal("192.168.3.1/24"),
		"remote_vpn_subnets": cty.ListVal([]cty.Value{cty.StringVal("192.168.3.0/24")}),
	}
	for k, v := range attrs {
		if v == cty.NilVal {
			delete(base, k)
			continue
		}
		base[k] = v
	}
	return cty.ObjectVal(base)
}

func wantErr(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected an error containing %q, got nil", want)
	}
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("expected an error containing %q, got: %v", want, err)
	}
}

func wantOK(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("expected the config to validate, got: %v", err)
	}
}

func TestValidateRemoteUserVPNRawConfig_valid(t *testing.T) {
	wantOK(t, validateRemoteUserVPNRawConfig(serverRaw(nil)))
}

// A null raw config is what a destroy plan supplies; it must not error.
func TestValidateRemoteUserVPNRawConfig_nullConfig(t *testing.T) {
	wantOK(t, validateRemoteUserVPNRawConfig(cty.NullVal(cty.EmptyObject)))
}

func TestValidateRemoteUserVPNRawConfig_requiresVPNType(t *testing.T) {
	wantErr(t, validateRemoteUserVPNRawConfig(serverRaw(map[string]cty.Value{"vpn_type": cty.NilVal})),
		`"vpn_type" is required when purpose = "remote-user-vpn"`)
}

func TestValidateRemoteUserVPNRawConfig_requiresSubnet(t *testing.T) {
	wantErr(t, validateRemoteUserVPNRawConfig(serverRaw(map[string]cty.Value{"subnet": cty.NilVal})),
		`"subnet" (the VPN Server's own tunnel address) is required`)
}

// Either an explicit pool or controller allocation, never neither: with both
// absent the server has no addresses to hand out.
func TestValidateRemoteUserVPNRawConfig_poolOrDynamic(t *testing.T) {
	wantErr(t, validateRemoteUserVPNRawConfig(serverRaw(map[string]cty.Value{"remote_vpn_subnets": cty.NilVal})),
		`"remote_vpn_subnets" is required`)

	wantOK(t, validateRemoteUserVPNRawConfig(serverRaw(map[string]cty.Value{
		"remote_vpn_subnets":                 cty.NilVal,
		"remote_vpn_dynamic_subnets_enabled": cty.True,
	})))

	// Explicitly false is the same as absent for this rule.
	wantErr(t, validateRemoteUserVPNRawConfig(serverRaw(map[string]cty.Value{
		"remote_vpn_subnets":                 cty.NilVal,
		"remote_vpn_dynamic_subnets_enabled": cty.False,
	})), `"remote_vpn_subnets" is required`)
}

// An interpolated value is unknown at plan time but is still "set", so it must
// satisfy the requirement rather than trip a false "required" error.
func TestValidateRemoteUserVPNRawConfig_unknownCountsAsSet(t *testing.T) {
	wantOK(t, validateRemoteUserVPNRawConfig(serverRaw(map[string]cty.Value{
		"remote_vpn_subnets": cty.UnknownVal(cty.List(cty.String)),
	})))
}

// The server-only fields must not leak onto other purposes.
func TestValidateRemoteUserVPNRawConfig_rejectsServerFieldsElsewhere(t *testing.T) {
	for _, field := range []string{
		"remote_vpn_subnets", "remote_vpn_dynamic_subnets_enabled",
		"uid_vpn_type", "uid_vpn_masquerade_enabled",
		"uid_vpn_max_connection_time_seconds", "uid_vpn_default_dns_suffix",
		"uid_vpn_sync_public_ip",
	} {
		attrs := map[string]cty.Value{
			"purpose": cty.StringVal("corporate"),
			"subnet":  cty.StringVal("10.10.1.1/24"),
		}
		switch field {
		case "remote_vpn_subnets":
			attrs[field] = cty.ListVal([]cty.Value{cty.StringVal("10.0.0.0/24")})
		case "uid_vpn_type", "uid_vpn_default_dns_suffix":
			attrs[field] = cty.StringVal("x")
		case "uid_vpn_max_connection_time_seconds":
			attrs[field] = cty.NumberIntVal(3600)
		default:
			attrs[field] = cty.True
		}
		err := validateRemoteUserVPNRawConfig(cty.ObjectVal(attrs))
		wantErr(t, err, `"`+field+`" is only valid when purpose = "remote-user-vpn"`)
	}
}

// vpn_type is shared between the two VPN purposes, so each value stays pinned to
// its own purpose rather than being accepted on both.
func TestValidateRemoteUserVPNRawConfig_vpnTypePinnedToPurpose(t *testing.T) {
	wantErr(t, validateRemoteUserVPNRawConfig(serverRaw(map[string]cty.Value{
		"vpn_type": cty.StringVal("wireguard-client"),
	})), `vpn_type "wireguard-client" is only valid when purpose = "vpn-client"`)

	wantErr(t, validateRemoteUserVPNRawConfig(cty.ObjectVal(map[string]cty.Value{
		"purpose":  cty.StringVal("corporate"),
		"vpn_type": cty.StringVal("wireguard-server"),
	})), `vpn_type "wireguard-server" is only valid when purpose = "remote-user-vpn"`)

	// The vpn-client purpose keeps its own type.
	wantOK(t, validateRemoteUserVPNRawConfig(cty.ObjectVal(map[string]cty.Value{
		"purpose":  cty.StringVal("vpn-client"),
		"vpn_type": cty.StringVal("wireguard-client"),
	})))
}

// Enum coverage: the new values must be accepted and the still-unmodelled ones
// must not be.
func TestNetworkEnums_pass2(t *testing.T) {
	purpose := ResourceNetwork().Schema["purpose"]
	if _, errs := purpose.ValidateFunc("remote-user-vpn", "purpose"); len(errs) != 0 {
		t.Errorf("purpose \"remote-user-vpn\" should be accepted, got: %v", errs)
	}
	if _, errs := purpose.ValidateFunc("site-vpn", "purpose"); len(errs) == 0 {
		t.Error("purpose \"site-vpn\" is not modelled and should still be rejected")
	}

	vpnType := ResourceNetwork().Schema["vpn_type"]
	for _, ok := range []string{"wireguard-server", "wireguard-client"} {
		if _, errs := vpnType.ValidateFunc(ok, "vpn_type"); len(errs) != 0 {
			t.Errorf("vpn_type %q should be accepted, got: %v", ok, errs)
		}
	}
	if _, errs := vpnType.ValidateFunc("openvpn-server", "vpn_type"); len(errs) == 0 {
		t.Error("vpn_type \"openvpn-server\" is not modelled and should be rejected")
	}
}
