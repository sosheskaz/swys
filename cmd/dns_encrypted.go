package cmd

import (
	"crypto/tls"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/sosheskaz-systems/npc/internal/dnsquery"
)

func parseDNSEndpoint(query *dnsQuery) error {
	var port *uint16
	if query.portSet {
		value := uint16(query.port) //nolint:gosec // validateDNSLimitOptions bounds the value.
		port = &value
	}
	endpoint, err := dnsquery.ParseEndpoint(query.server, port)
	if err != nil {
		return fmt.Errorf("%w: %w", errInvalidDNSOptions, err)
	}
	query.endpoint = &endpoint
	query.transport = string(endpoint.Transport)
	query.server = endpoint.Address()
	return nil
}

func validateEncryptedDNSOptions(cmd *cobra.Command) error {
	certPath, err := cmd.Flags().GetString(tlsCertFlagName)
	if err != nil {
		return fmt.Errorf("read cert flag: %w", err)
	}
	keyPath, err := cmd.Flags().GetString(tlsKeyFlagName)
	if err != nil {
		return fmt.Errorf("read key flag: %w", err)
	}
	if (certPath == "") != (keyPath == "") {
		return fmt.Errorf("%w: --cert and --key must be specified together", errInvalidDNSOptions)
	}
	caPath, err := cmd.Flags().GetString(tlsCAFlagName)
	if err != nil {
		return fmt.Errorf("read ca flag: %w", err)
	}
	systemCA, err := cmd.Flags().GetBool("system-ca")
	if err != nil {
		return fmt.Errorf("read system-ca flag: %w", err)
	}
	insecure, err := cmd.Flags().GetBool("insecure")
	if err != nil {
		return fmt.Errorf("read insecure flag: %w", err)
	}
	if systemCA && caPath == "" {
		return fmt.Errorf("%w: --system-ca requires --ca", errInvalidDNSOptions)
	}
	if insecure && (caPath != "" || systemCA) {
		return fmt.Errorf("%w: --insecure cannot be combined with --ca or --system-ca", errInvalidDNSOptions)
	}
	return validateCertificatePaths(cmd, tlsCertFlagName, tlsKeyFlagName, tlsCAFlagName)
}

func encryptedDNSTLSConfig(cmd *cobra.Command) (*tls.Config, error) {
	serverName, err := cmd.Flags().GetString(tlsServerNameFlagName)
	if err != nil {
		return nil, fmt.Errorf("read servername flag: %w", err)
	}
	insecure, err := cmd.Flags().GetBool("insecure")
	if err != nil {
		return nil, fmt.Errorf("read insecure flag: %w", err)
	}
	config := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: serverName, InsecureSkipVerify: insecure}
	if err := addTLSRootCAs(cmd, config); err != nil {
		return nil, err
	}
	identity, exists, err := tlsClientIdentityFromCommand(cmd)
	if err != nil {
		return nil, err
	}
	if exists {
		config.Certificates = []tls.Certificate{identity}
	}
	return config, nil
}
