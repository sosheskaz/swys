package cmd

import (
	"errors"
	"fmt"
	"io"
	"net"

	"github.com/spf13/cobra"

	"github.com/sosheskaz-systems/npc/internal/netconn"
)

var netListenCmd = &cobra.Command{
	Use:   "listen",
	Short: "Listen for one incoming connection",
}

var netListenTCPCmd = binaryOutputCommand(listenStreamNetworkCommand(&cobra.Command{
	Use:   "tcp host:port",
	Short: "Exchange raw bytes over one accepted TCP connection",
	RunE:  runNetListenTCP,
}), true)

func runNetListenTCP(cmd *cobra.Command, args []string) error {
	options, err := networkStreamOptionsFromCommand(cmd)
	if err != nil {
		return err
	}
	setupContext, cancel := networkSetupContext(cmd.Context(), options.timeout)
	defer cancel()

	listener, err := netconn.ListenTCP(setupContext, args[0])
	if err != nil {
		return err
	}
	if options.verbose {
		if err := writeTCPListeningDetails(cmd.ErrOrStderr(), listener); err != nil {
			return errors.Join(err, listener.Close())
		}
	}
	connection, err := netconn.AcceptTCP(setupContext, listener)
	if err != nil {
		return err
	}
	if options.verbose {
		if err := writeTCPAcceptedDetails(cmd.ErrOrStderr(), connection); err != nil {
			return errors.Join(err, connection.Close())
		}
	}
	return netconn.Relay(
		cmd.Context(),
		connection,
		cmd.InOrStdin(),
		cmd.OutOrStdout(),
		options.wait,
		options.closeWrite,
	)
}

func writeTCPListeningDetails(output io.Writer, listener net.Listener) error {
	if _, err := fmt.Fprintf(output, "listening tcp %s\n", listener.Addr()); err != nil {
		return fmt.Errorf("write TCP listener details: %w", err)
	}
	return nil
}

func writeTCPAcceptedDetails(output io.Writer, connection net.Conn) error {
	if _, err := fmt.Fprintf(
		output,
		"accepted tcp %s <- %s\n",
		connection.LocalAddr(),
		connection.RemoteAddr(),
	); err != nil {
		return fmt.Errorf("write accepted TCP connection details: %w", err)
	}
	return nil
}

func init() {
	netCmd.AddCommand(netListenCmd)
	netListenCmd.AddCommand(netListenTCPCmd)
}
