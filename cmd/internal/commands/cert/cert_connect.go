package cert

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"

	"github.com/spf13/cobra"

	"github.com/sosheskaz-systems/npc/cmd/internal/cli/commandio"
	"github.com/sosheskaz-systems/npc/internal/asym"
	"github.com/sosheskaz-systems/npc/internal/netconn"
)

func newConnectCmd() *cobra.Command {
	cmd := commandio.NetworkCommand(commandio.StructuredOutputCommand(&cobra.Command{
		Aliases: []string{"c", "conn"},
		Use:     "connect host:port",
		Short:   "Fetch and display certificates from a TLS connection",
		RunE:    runPreparedInspection,
	}, certFormatNames))
	commandio.AddOutputEncodingFlag(cmd)
	addCertificateSelection(cmd, asym.SelectLeaf)
	cmd.ValidArgsFunction = cobra.NoFileCompletions
	return cmd
}

func prepareConnectedCertificates(cmd *cobra.Command, _ io.Reader) ([]byte, error) {
	address := cmd.Flags().Args()[0]
	dnsName, _, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("parse TLS address %q: %w", address, err)
	}
	timeout, err := cmd.Flags().GetDuration(commandio.TimeoutFlagName)
	if err != nil {
		return nil, fmt.Errorf("read timeout flag: %w", err)
	}
	// Preparation precedes RunE, so its connection needs its own setup deadline.
	ctx, cancel := commandio.NetworkSetupContext(cmd.Context(), timeout)
	defer cancel()
	connection, err := netconn.DialTLS(ctx, address, &tls.Config{
		// Retrieval and trust reporting are separate, including for private roots.
		InsecureSkipVerify: true, //nolint:gosec // diagnostic retrieval reports verification separately
		ServerName:         dnsName,
	})
	if err != nil {
		return nil, err
	}
	defer connection.Close() //nolint:errcheck // peer certificates are already in memory
	certs := connection.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return nil, errNoPeerCertificates
	}
	return prepareInspection(cmd, certs, &x509.VerifyOptions{DNSName: dnsName}, "peer")
}
