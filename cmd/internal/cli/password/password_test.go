package password_test

import (
	"bytes"
	"context"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/sosheskaz-systems/npc/cmd/internal/cli/password"
)

func TestCommandFirstLineAndBoundedOutput(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("POSIX command")
	}
	var diagnostics bytes.Buffer
	got, err := password.Command(t.Context(), "printf '  secret  \\r\\nignored\\n'", &diagnostics)
	require.NoError(t, err)
	require.Equal(t, []byte("  secret  "), got)
	require.Empty(t, diagnostics.String())
	_, err = password.Command(t.Context(), "printf '%s\\n' 'secret'; exit 7", &diagnostics)
	require.Error(t, err)
	require.NotContains(t, err.Error(), "secret")
	_, err = password.Command(t.Context(), "printf '%*s' 70000 ''", &diagnostics)
	require.Error(t, err)
	require.Contains(t, err.Error(), "65536")
}

func TestCommandCancellationReapsShell(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("POSIX command")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := password.Command(ctx, "sleep 10", &bytes.Buffer{})
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.Less(t, time.Since(start), 3*time.Second)
}

func TestEnvironmentPreservesBytesAndRejectsEmpty(t *testing.T) {
	t.Setenv("NPC_PASSWORD_TEST", "  é  ")
	got, err := password.Environment("NPC_PASSWORD_TEST")
	require.NoError(t, err)
	require.Equal(t, []byte("  é  "), got)
	t.Setenv("NPC_PASSWORD_TEST", "")
	_, err = password.Environment("NPC_PASSWORD_TEST")
	require.Error(t, err)
	_, err = password.Environment("NPC_PASSWORD_TEST_MISSING")
	require.Error(t, err)
	require.NotErrorIs(t, err, context.Canceled)
	require.NotContains(t, strings.ToLower(err.Error()), "é")
}
