// Copyright 2020 Matthew Holt
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package dynamicdns

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"
)

func init() {
	caddy.RegisterModule(App{})
}

type App struct {
	// The configuration for the Windows DNS server
	DNSServer struct {
		Host     string `json:"host,omitempty"`
		User     string `json:"user,omitempty"`
		Password string `json:"password,omitempty"`
	} `json:"dns_server,omitempty"`

	// The record names, keyed by DNS zone, for which to update the CNAME records.
	Domains map[string][]string `json:"domains,omitempty"`

	// How frequently to check and update DNS records. Default: 30m
	CheckInterval caddy.Duration `json:"check_interval,omitempty"`

	// The TTL to set on DNS records.
	TTL caddy.Duration `json:"ttl,omitempty"`

	// If true, automatically create CNAME records for r"everse proxies
	AutoCNAME bool `json:"auto_cname,omitempty"`

	// The zone to use for automatic CNAME records
	AutoCNAMEZone string `json:"auto_cname_zone,omitempty"`

	ctx    caddy.Context
	logger *zap.Logger
}

func (App) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "dynamic_dns",
		New: func() caddy.Module { return new(App) },
	}
}

func (a *App) Provision(ctx caddy.Context) error {
	a.ctx = ctx
	a.logger = ctx.Logger(a)

	if a.CheckInterval == 0 {
		a.CheckInterval = caddy.Duration(defaultCheckInterval)
	}
	if time.Duration(a.CheckInterval) < time.Second {
		return fmt.Errorf("check interval must be at least 1 second")
	}

	return nil
}

func (a *App) Start() error {
	if a.AutoCNAMEZone != "" {
		err := a.addReverseProxyCNAMEs()
		if err != nil {
			return fmt.Errorf("failed to add reverse proxy CNAMEs: %v", err)
		}
	}

	go a.checkerLoop()
	return nil
}

func (a *App) Stop() error {
	return nil
}

func (a *App) checkerLoop() {
	ticker := time.NewTicker(time.Duration(a.CheckInterval))
	defer ticker.Stop()

	a.updateDNS()

	for {
		select {
		case <-ticker.C:
			a.updateDNS()
		case <-a.ctx.Done():
			return
		}
	}
}

func (a *App) updateDNS() {
	a.logger.Debug("beginning DNS update")

	allDomains := a.allDomains()

	for zone, domains := range allDomains {
		for _, domain := range domains {
			err := a.updateCNAME(zone, domain)
			if err != nil {
				a.logger.Error("failed updating CNAME record",
					zap.String("zone", zone),
					zap.String("domain", domain),
					zap.Error(err))
			} else {
				a.logger.Info("updated CNAME record",
					zap.String("zone", zone),
					zap.String("domain", domain))
			}
		}
	}

	a.logger.Info("finished updating DNS")
}

func (a *App) updateCNAME(zone, domain string) error {
	config := &ssh.ClientConfig{
		User: a.DNSServer.User,
		Auth: []ssh.AuthMethod{
			ssh.Password(a.DNSServer.Password),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	client, err := ssh.Dial("tcp", a.DNSServer.Host+":22", config)
	if err != nil {
		return fmt.Errorf("failed to dial: %v", err)
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("failed to create session: %v", err)
	}
	defer session.Close()

	cmd := fmt.Sprintf("Add-DnsServerResourceRecordCName -ZoneName %s -Name %s -HostNameAlias %s", zone, domain, zone)
	fullCmd := fmt.Sprintf("powershell -Command \"%s\"", cmd)

	output, err := session.CombinedOutput(fullCmd)
	if err != nil {
		return fmt.Errorf("failed to run command: %v, output: %s", err, string(output))
	}

	if strings.Contains(string(output), "Error") {
		return fmt.Errorf("DNS record update failed: %s", string(output))
	}

	return nil
}

func (a *App) allDomains() map[string][]string {
	return a.Domains
}

func (a *App) addReverseProxyCNAMEs() error {
	// Get the HTTP app
	httpAppIface, err := a.ctx.App("http")
	if err != nil {
		return fmt.Errorf("failed to get HTTP app: %v", err)
	}
	httpApp := httpAppIface.(*caddyhttp.App)

	// Iterate over all servers and routes
	for _, server := range httpApp.Servers {
		for _, route := range server.Routes {
			// Check if this route has a reverse proxy
			for _, rawHandler := range route.HandlersRaw {
				var handler map[string]interface{}
				err := json.Unmarshal(rawHandler, &handler)
				if err != nil {
					return fmt.Errorf("failed to unmarshal handler: %v", err)
				}

				// Check if this handler is a reverse proxy
				if handlerType, ok := handler["handler"].(string); ok && handlerType == "reverse_proxy" {
					// This is a reverse proxy. Get the hostname from the matcher.
					for _, matcherSet := range route.MatcherSets {
						for _, matcher := range matcherSet {
							if hostMatcher, ok := matcher.(caddyhttp.MatchHost); ok {
								for _, host := range hostMatcher {
									// Add this host to our domains
									if a.Domains == nil {
										a.Domains = make(map[string][]string)
									}
									a.Domains[a.AutoCNAMEZone] = append(a.Domains[a.AutoCNAMEZone], strings.TrimSuffix(host, "."+a.AutoCNAMEZone))
								}
							}
						}
					}
				}
			}
		}
	}

	return nil
}

const defaultCheckInterval = 30 * time.Minute

// Interface guards
var (
	_ caddy.Provisioner = (*App)(nil)
	_ caddy.App         = (*App)(nil)
)
