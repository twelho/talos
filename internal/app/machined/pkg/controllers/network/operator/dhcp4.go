// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package operator

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/cosi-project/runtime/pkg/resource"
	"github.com/cosi-project/runtime/pkg/state"
	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv4/nclient4"
	"go.uber.org/zap"
	"inet.af/netaddr"

	"github.com/talos-systems/talos/internal/app/machined/pkg/runtime"
	"github.com/talos-systems/talos/pkg/machinery/generic/slices"
	"github.com/talos-systems/talos/pkg/machinery/nethelpers"
	"github.com/talos-systems/talos/pkg/machinery/resources/network"
)

// DHCP4 implements the DHCPv4 network operator.
type DHCP4 struct {
	logger *zap.Logger
	state  state.State

	linkName    string
	routeMetric uint32
	requestMTU  bool

	offer *dhcpv4.DHCPv4

	mu          sync.Mutex
	addresses   []network.AddressSpecSpec
	links       []network.LinkSpecSpec
	routes      []network.RouteSpecSpec
	hostname    []network.HostnameSpecSpec
	resolvers   []network.ResolverSpecSpec
	timeservers []network.TimeServerSpecSpec
}

// NewDHCP4 creates DHCPv4 operator.
func NewDHCP4(logger *zap.Logger, linkName string, routeMetric uint32, platform runtime.Platform, state state.State) *DHCP4 {
	return &DHCP4{
		logger:      logger,
		state:       state,
		linkName:    linkName,
		routeMetric: routeMetric,
		// <3 azure
		// When including dhcp.OptionInterfaceMTU we don't get a dhcp offer back on azure.
		// So we'll need to explicitly exclude adding this option for azure.
		requestMTU: platform.Name() != "azure",
	}
}

// Prefix returns unique operator prefix which gets prepended to each spec.
func (d *DHCP4) Prefix() string {
	return fmt.Sprintf("dhcp4/%s", d.linkName)
}

// hostnameStatusMetadata represents the full metadata of any version of a network.HostnameStatus.
var hostnameStatusMetadata = resource.NewMetadata(network.NamespaceName, network.HostnameStatusType, network.HostnameID, resource.VersionUndefined)

// extractHostname extracts a hostname from the given resource if it is a valid network.HostnameStatus.
func extractHostname(res resource.Resource) string {
	if res, ok := res.(*network.HostnameStatus); ok {
		return res.TypedSpec().Hostname
	}

	return ""
}

// setupHostnameWatch returns the initial hostname and a channel that outputs all events related to hostname changes.
func (d *DHCP4) setupHostnameWatch(ctx context.Context) (string, <-chan state.Event, error) {
	hostnameWatchCh := make(chan state.Event)
	if err := d.state.Watch(ctx, hostnameStatusMetadata, hostnameWatchCh); err != nil {
		return "", nil, err
	}

	return extractHostname((<-hostnameWatchCh).Resource), hostnameWatchCh, nil
}

// knownHostname checks if the given hostname has been defined by this operator.
func (d *DHCP4) knownHostname(hostname string) bool {
	for i := range d.hostname {
		if d.hostname[i].Hostname == hostname {
			return true
		}
	}

	return false
}

// Run the operator loop.
//
//nolint:gocyclo,dupl
func (d *DHCP4) Run(ctx context.Context, notifyCh chan<- struct{}) {
	const minRenewDuration = 5 * time.Second // protect from renewing too often

	renewInterval := minRenewDuration

	hostname, hostnameWatchCh, err := d.setupHostnameWatch(ctx)
	if err != nil && !errors.Is(err, context.Canceled) {
		d.logger.Warn("failed to watch for hostname changes", zap.Error(err))
	}

	for {
		// always request a hostname from DHCP together with a lease negotiation
		requestHostname := d.offer == nil

		leaseTime, err := d.requestRenew(ctx, hostname)
		if err != nil && !errors.Is(err, context.Canceled) {
			d.logger.Warn("request/renew failed", zap.Error(err), zap.String("link", d.linkName))
		}

		if err == nil {
			select {
			case notifyCh <- struct{}{}:
			case <-ctx.Done():
				return
			}
		}

		// DHCP hostname parroting protection: if e.g. `dnsmasq` receives a request that both sends
		// a hostname and requests one, it will "parrot" the sent hostname back if no other name
		// has been defined for the requesting host. That causes update anomalies, since removing a
		// hostname defined previously by e.g. the configuration layer causes a copy of that
		// hostname to live on in a spec defined by this operator, even though it isn't sourced from
		// DHCP.
		//
		// To avoid this issue, never send and request a hostname in the same operation. When
		// negotiating a new lease, send the current hostname when acquiring the lease, and follow
		// up with a dedicated INFORM request to ask the server for a DCHP-defined hostname. When
		// renewing a lease, we're free to always request a hostname (to detect server-side
		// changes), since any changes to the node hostname will cause a lease invalidation and
		// re-start the negotiation process. More details below.
		if requestHostname {
			// this must be invoked after the controller has been informed
			// once since it uses unicast with the previously defined address
			err = d.requestHostname(ctx)
			if err != nil && !errors.Is(err, context.Canceled) {
				d.logger.Warn("hostname request failed", zap.Error(err), zap.String("link", d.linkName))
			}

			if err == nil {
				select {
				case notifyCh <- struct{}{}:
				case <-ctx.Done():
					return
				}
			}
		}

		if leaseTime > 0 {
			renewInterval = leaseTime / 2
		} else {
			renewInterval /= 2
		}

		if renewInterval < minRenewDuration {
			renewInterval = minRenewDuration
		}

		for {
			select {
			case <-ctx.Done():
				return
			case <-time.After(renewInterval):
			case event := <-hostnameWatchCh:
				// If the hostname resource was deleted entirely, we must still  inform the DHCP
				// server that the node has no hostname anymore. `extractHostname` will return a
				// blank hostname for a Tombstone resource generated by a deletion event.
				hostname = extractHostname(event.Resource)

				// If, on first invocation, the DHCP server has given a new hostname for the node,
				// and the network.HostnameSpecController decides to apply it as a preferred
				// hostname, this operator would unnecessarily drop the lease and restart DHCP
				// discovery. Thus, if the selected hostname has been sourced from this operator,
				// we don't need to do anything.
				if d.knownHostname(hostname) {
					continue
				}

				// While updating the hostname together with a RENEW request works for dnsmasq, it
				// doesn't work with the Windows Server DHCP + DNS. A hostname update via an
				// INIT-REBOOT request also gets ignored. Thus, the only reliable way to update the
				// hostname seems to be to forget the old release and initiate a new DISCOVER flow
				// with the new hostname. RFC 2131 doesn't define any better way to do this, and
				// since according to the spec the DISCOVER cannot be targeted at the previous
				// lessor, the node may switch DHCP servers on hostname change. This is not that
				// big of a concern though, since a single network should not have multiple
				// competing DHCP servers in the first place.
				d.offer = nil
			}

			break
		}
	}
}

// AddressSpecs implements Operator interface.
func (d *DHCP4) AddressSpecs() []network.AddressSpecSpec {
	d.mu.Lock()
	defer d.mu.Unlock()

	return d.addresses
}

// LinkSpecs implements Operator interface.
func (d *DHCP4) LinkSpecs() []network.LinkSpecSpec {
	d.mu.Lock()
	defer d.mu.Unlock()

	return d.links
}

// RouteSpecs implements Operator interface.
func (d *DHCP4) RouteSpecs() []network.RouteSpecSpec {
	d.mu.Lock()
	defer d.mu.Unlock()

	return d.routes
}

// HostnameSpecs implements Operator interface.
func (d *DHCP4) HostnameSpecs() []network.HostnameSpecSpec {
	d.mu.Lock()
	defer d.mu.Unlock()

	return d.hostname
}

// ResolverSpecs implements Operator interface.
func (d *DHCP4) ResolverSpecs() []network.ResolverSpecSpec {
	d.mu.Lock()
	defer d.mu.Unlock()

	return d.resolvers
}

// TimeServerSpecs implements Operator interface.
func (d *DHCP4) TimeServerSpecs() []network.TimeServerSpecSpec {
	d.mu.Lock()
	defer d.mu.Unlock()

	return d.timeservers
}

func (d *DHCP4) parseHostnameFromAck(ack *dhcpv4.DHCPv4) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if ack.HostName() != "" {
		spec := network.HostnameSpecSpec{
			ConfigLayer: network.ConfigOperator,
		}

		if err := spec.ParseFQDN(ack.HostName()); err == nil {
			if ack.DomainName() != "" {
				spec.Domainname = ack.DomainName()
			}

			d.hostname = []network.HostnameSpecSpec{
				spec,
			}
		} else {
			d.hostname = nil
		}
	} else {
		d.hostname = nil
	}
}

//nolint:gocyclo
func (d *DHCP4) parseNetworkConfigFromAck(ack *dhcpv4.DHCPv4) {
	d.mu.Lock()
	defer d.mu.Unlock()

	addr, _ := netaddr.FromStdIPNet(&net.IPNet{
		IP:   ack.YourIPAddr,
		Mask: ack.SubnetMask(),
	})

	d.addresses = []network.AddressSpecSpec{
		{
			Address:     addr,
			LinkName:    d.linkName,
			Family:      nethelpers.FamilyInet4,
			Scope:       nethelpers.ScopeGlobal,
			Flags:       nethelpers.AddressFlags(nethelpers.AddressPermanent),
			ConfigLayer: network.ConfigOperator,
		},
	}

	mtu, err := dhcpv4.GetUint16(dhcpv4.OptionInterfaceMTU, ack.Options)
	if err == nil {
		d.links = []network.LinkSpecSpec{
			{
				Name: d.linkName,
				MTU:  uint32(mtu),
				Up:   true,
			},
		}
	} else {
		d.links = nil
	}

	// rfc3442:
	//   If the DHCP server returns both a Classless Static Routes option and
	//   a Router option, the DHCP client MUST ignore the Router option.
	d.routes = nil

	if len(ack.ClasslessStaticRoute()) > 0 {
		for _, route := range ack.ClasslessStaticRoute() {
			gw, _ := netaddr.FromStdIP(route.Router)
			dst, _ := netaddr.FromStdIPNet(route.Dest)

			d.routes = append(d.routes, network.RouteSpecSpec{
				Family:      nethelpers.FamilyInet4,
				Destination: dst,
				Source:      addr.IP(),
				Gateway:     gw,
				OutLinkName: d.linkName,
				Table:       nethelpers.TableMain,
				Priority:    d.routeMetric,
				Scope:       nethelpers.ScopeGlobal,
				Type:        nethelpers.TypeUnicast,
				Protocol:    nethelpers.ProtocolBoot,
				ConfigLayer: network.ConfigOperator,
			})
		}
	} else {
		for _, router := range ack.Router() {
			gw, _ := netaddr.FromStdIP(router)

			d.routes = append(d.routes, network.RouteSpecSpec{
				Family:      nethelpers.FamilyInet4,
				Gateway:     gw,
				Source:      addr.IP(),
				OutLinkName: d.linkName,
				Table:       nethelpers.TableMain,
				Priority:    d.routeMetric,
				Scope:       nethelpers.ScopeGlobal,
				Type:        nethelpers.TypeUnicast,
				Protocol:    nethelpers.ProtocolBoot,
				ConfigLayer: network.ConfigOperator,
			})

			if !addr.Contains(gw) {
				// add an interface route for the gateway if it's not in the same network
				d.routes = append(d.routes, network.RouteSpecSpec{
					Family:      nethelpers.FamilyInet4,
					Destination: netaddr.IPPrefixFrom(gw, gw.BitLen()),
					Source:      addr.IP(),
					OutLinkName: d.linkName,
					Table:       nethelpers.TableMain,
					Priority:    d.routeMetric,
					Scope:       nethelpers.ScopeLink,
					Type:        nethelpers.TypeUnicast,
					Protocol:    nethelpers.ProtocolBoot,
					ConfigLayer: network.ConfigOperator,
				})
			}
		}
	}

	for i := range d.routes {
		d.routes[i].Normalize()
	}

	if len(ack.DNS()) > 0 {
		convertIP := func(ip net.IP) netaddr.IP {
			result, _ := netaddr.FromStdIP(ip)

			return result
		}

		d.resolvers = []network.ResolverSpecSpec{
			{
				DNSServers:  slices.Map(ack.DNS(), convertIP),
				ConfigLayer: network.ConfigOperator,
			},
		}
	} else {
		d.resolvers = nil
	}

	if len(ack.NTPServers()) > 0 {
		convertIP := func(ip net.IP) string {
			result, _ := netaddr.FromStdIP(ip)

			return result.String()
		}

		d.timeservers = []network.TimeServerSpecSpec{
			{
				NTPServers:  slices.Map(ack.NTPServers(), convertIP),
				ConfigLayer: network.ConfigOperator,
			},
		}
	} else {
		d.timeservers = nil
	}
}

func (d *DHCP4) newClient() (*nclient4.Client, error) {
	var clientOpts []nclient4.ClientOpt

	// we have an existing lease, target the server with unicast
	if d.offer != nil {
		serverAddr, err := ToUDPAddr(d.offer.ServerIPAddr, nclient4.ServerPort)
		if err != nil {
			return nil, err
		}

		clientAddr, err := ToUDPAddr(d.offer.YourIPAddr, nclient4.ClientPort)
		if err != nil {
			return nil, err
		}

		// RFC 2131, section 4.3.2:
		//     DHCPREQUEST generated during RENEWING state:
		//     ... This message will be unicast, so no relay
		//     agents will be involved in its transmission.
		clientOpts = append(clientOpts,
			nclient4.WithServerAddr(serverAddr),
			// WithUnicast must be specified manually, WithServerAddr is not enough
			nclient4.WithUnicast(clientAddr),
		)
	}

	// create a new client
	return nclient4.New(d.linkName, clientOpts...)
}

// requestHostname uses an INFORM request to request a hostname from DHCP as requesting
// it during a DISCOVER is not reliable when simultaneously sending the local hostname.
func (d *DHCP4) requestHostname(ctx context.Context) error {
	opts := []dhcpv4.OptionCode{
		dhcpv4.OptionHostName,
		dhcpv4.OptionDomainName,
	}

	client, err := d.newClient()
	if err != nil {
		return err
	}

	//nolint:errcheck
	defer client.Close()

	d.logger.Debug("DHCP INFORM", zap.String("link", d.linkName))

	// acquire a hostname using an additional INFORM request
	ack, err := client.InformFromOffer(ctx, d.offer, dhcpv4.WithRequestedOptions(opts...))
	if err != nil {
		return err
	}

	d.logger.Debug("DHCP ACK", zap.String("link", d.linkName), zap.String("dhcp", collapseSummary(ack.Summary())))

	// parse the hostname from the response
	d.parseHostnameFromAck(ack)

	return nil
}

func (d *DHCP4) requestRenew(ctx context.Context, hostname string) (time.Duration, error) {
	opts := []dhcpv4.OptionCode{
		dhcpv4.OptionClasslessStaticRoute,
		dhcpv4.OptionDomainNameServer,
		// TODO(twelho): This is unused until network.ResolverSpec supports search domains
		dhcpv4.OptionDNSDomainSearchList,
		dhcpv4.OptionNTPServers,
		dhcpv4.OptionDomainName,
	}

	if d.requestMTU {
		opts = append(opts, dhcpv4.OptionInterfaceMTU)
	}

	// always request a hostname during renewals
	if d.offer != nil {
		opts = append(opts, dhcpv4.OptionHostName)
	}

	mods := []dhcpv4.Modifier{dhcpv4.WithRequestedOptions(opts...)}

	// if the system has a hostname and there is no existing lease (i.e. this is not
	// a lease renewal), send the current hostname to the DHCP server with option 12
	if d.offer == nil && len(hostname) > 0 {
		mods = append(mods, dhcpv4.WithOption(dhcpv4.OptHostName(hostname)))
	}

	client, err := d.newClient()
	if err != nil {
		return 0, err
	}

	//nolint:errcheck
	defer client.Close()

	var lease *nclient4.Lease

	if d.offer != nil {
		d.logger.Debug("DHCP RENEW", zap.String("link", d.linkName))
		lease, err = client.Renew(ctx, d.offer, mods...)
	} else {
		d.logger.Debug("DHCP REQUEST", zap.String("link", d.linkName))
		lease, err = client.Request(ctx, mods...)
	}

	// clear offer if request fails to start with discover sequence next time
	if err != nil {
		d.offer = nil

		return 0, err
	}

	d.logger.Debug("DHCP ACK", zap.String("link", d.linkName), zap.String("dhcp", collapseSummary(lease.ACK.Summary())))

	d.parseNetworkConfigFromAck(lease.ACK)

	// only parse the hostname during renewals as it isn't requested when requesting a new lease
	if d.offer != nil {
		d.parseHostnameFromAck(lease.ACK)
	}

	d.offer = lease.Offer

	return lease.ACK.IPAddressLeaseTime(time.Minute * 30), nil
}

func collapseSummary(summary string) string {
	lines := strings.Split(summary, "\n")[1:]

	for i := range lines {
		lines[i] = strings.TrimSpace(lines[i])
	}

	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}

	return strings.Join(lines, ", ")
}
