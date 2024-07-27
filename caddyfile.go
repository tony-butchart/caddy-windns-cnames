package dynamicdns

import (
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
)

func init() {
	httpcaddyfile.RegisterGlobalOption("dynamic_dns", parseApp)
}

// parseApp configures the "dynamic_dns" global option from Caddyfile.
// Syntax:
//
//	dynamic_dns {
//	    domains {
//	        <zone> <names...>
//	    }
//	    check_interval <duration>
//	    dns_server {
//	        host <host>
//	        user <user>
//	        password <password>
//	    }
//	    ttl <duration>
//	    auto_cname [<zone>]
//	}
//
// If <names...> are omitted after <zone>, then "@" will be assumed.
func parseApp(d *caddyfile.Dispenser, _ interface{}) (interface{}, error) {
	app := new(App)

	// consume the option name
	if !d.Next() {
		return nil, d.ArgErr()
	}

	// handle the block
	for d.NextBlock(0) {
		switch d.Val() {
		case "domains":
			for nesting := d.Nesting(); d.NextBlock(nesting); {
				zone := d.Val()
				if zone == "" {
					return nil, d.ArgErr()
				}
				names := d.RemainingArgs()
				if len(names) == 0 {
					names = []string{"@"}
				}
				if app.Domains == nil {
					app.Domains = make(map[string][]string)
				}
				app.Domains[zone] = append(app.Domains[zone], names...)
			}
		case "check_interval":
			if !d.NextArg() {
				return nil, d.ArgErr()
			}
			dur, err := caddy.ParseDuration(d.Val())
			if err != nil {
				return nil, err
			}
			app.CheckInterval = caddy.Duration(dur)
		case "dns_server":
			for nesting := d.Nesting(); d.NextBlock(nesting); {
				switch d.Val() {
				case "host":
					if !d.NextArg() {
						return nil, d.ArgErr()
					}
					app.DNSServer.Host = d.Val()
				case "user":
					if !d.NextArg() {
						return nil, d.ArgErr()
					}
					app.DNSServer.User = d.Val()
				case "password":
					if !d.NextArg() {
						return nil, d.ArgErr()
					}
					app.DNSServer.Password = d.Val()
				default:
					return nil, d.Errf("unknown dns_server property '%s'", d.Val())
				}
			}
		case "ttl":
			if !d.NextArg() {
				return nil, d.ArgErr()
			}
			dur, err := caddy.ParseDuration(d.Val())
			if err != nil {
				return nil, err
			}
			app.TTL = caddy.Duration(dur)
		case "auto_cname":
			if !d.NextArg() {
				app.AutoCNAMEZone = d.Val()
			}
		default:
			return nil, d.ArgErr()
		}
	}

	return httpcaddyfile.App{
		Name:  "dynamic_dns",
		Value: caddyconfig.JSON(app, nil),
	}, nil
}
