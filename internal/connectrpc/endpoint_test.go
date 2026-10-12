package connectrpc_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/sosheskaz/swys/internal/connectrpc"
)

func TestEndpointForms(t *testing.T) {
	t.Parallel()
	for _, test := range []struct{ address, method, want string }{
		{"host:443/pkg.Service/Method", "", "https://host:443/pkg.Service/Method"},
		{"http://host:80", "pkg.Service/Method", "http://host:80/pkg.Service/Method"},
		{"https://host/Tenant%2FOne/", "/pkg.Service/Method", "https://host/Tenant%2FOne/pkg.Service/Method"},
		{"https://host/api/rpc/", "pkg.Service/Method", "https://host/api/rpc/pkg.Service/Method"},
	} {
		t.Run(test.want, func(t *testing.T) {
			t.Parallel()
			endpoint, err := connectrpc.ParseEndpoint(test.address, test.method)
			require.NoError(t, err)
			assert.Equal(t, test.want, endpoint.URL.String())
			assert.Equal(t, "/pkg.Service/Method", endpoint.Procedure)
		})
	}
	for _, test := range []struct{ address, method string }{
		{"ftp://host/pkg.Service/Method", ""},
		{"https://user:pass@host/pkg.Service/Method", ""},
		{"https://host/pkg.Service/Method?x=1", ""},
		{"https://host/pkg.Service/Method#section", ""},
		{"http://host", ""},
		{"http://host/pkg.Service/Method", "pkg.Service/Other"},
		{"http://host/pkg.Service/%4dethod", ""},
		{"http://host", "pkg.Service/Method/extra"},
	} {
		t.Run(test.address+test.method, func(t *testing.T) {
			t.Parallel()
			_, err := connectrpc.ParseEndpoint(test.address, test.method)
			require.ErrorIs(t, err, connectrpc.ErrEndpoint)
		})
	}
}
