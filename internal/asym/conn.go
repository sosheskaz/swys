package asym

import (
	"crypto/tls"
	"crypto/x509"
)

func CertFromDial(addr string) ([]*x509.Certificate, error) {
	conn, err := tls.Dial("tcp", addr, &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	return conn.ConnectionState().PeerCertificates, nil
}
