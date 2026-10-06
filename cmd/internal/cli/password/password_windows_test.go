//go:build windows

package password

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
	"unicode/utf16"
	"unsafe"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"

	"github.com/sosheskaz/swys/cmd/internal/cli/interrupt"
)

func TestWindowsConsoleInputRecordLayout(t *testing.T) {
	t.Parallel()
	require.Equal(t, uintptr(20), unsafe.Sizeof(consoleInputRecord{}))
	require.Equal(t, uintptr(14), unsafe.Offsetof(consoleInputRecord{}.char))
}

func TestWindowsHiddenInputKeys(t *testing.T) {
	t.Parallel()
	units, done, err := applyConsoleKey(nil, 'A')
	require.NoError(t, err)
	require.False(t, done)
	for _, unit := range utf16.Encode([]rune("😀")) {
		units, done, err = applyConsoleKey(units, unit)
		require.NoError(t, err)
		require.False(t, done)
	}
	units, done, err = applyConsoleKey(units, '\b')
	require.NoError(t, err)
	require.False(t, done)
	require.Equal(t, []uint16{'A'}, units)
	units, done, err = applyConsoleKey(units, '\r')
	require.NoError(t, err)
	require.True(t, done)
	require.Equal(t, "A", string(utf16.Decode(units)))
	_, _, err = applyConsoleKey(units, 3)
	var interrupted *interrupt.Error
	require.ErrorAs(t, err, &interrupted)
	require.ErrorIs(t, err, context.Canceled)
}

func TestWindowsQuotedPasswordCommand(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "password script.cmd")
	require.NoError(t, os.WriteFile(path, []byte("@echo off\r\necho quoted password\r\n"), 0o600))
	value, err := Command(t.Context(), `"`+path+`"`, &bytes.Buffer{})
	require.NoError(t, err)
	require.Equal(t, []byte("quoted password"), value)
	value, err = Command(t.Context(), `echo "quoted password"`, &bytes.Buffer{})
	require.NoError(t, err)
	require.Equal(t, []byte(`"quoted password"`), value)
}

func TestWindowsPasswordCommandFirstLine(t *testing.T) {
	t.Parallel()
	var diagnostics bytes.Buffer
	value, err := Command(t.Context(), "echo secret&echo ignored", &diagnostics)
	require.NoError(t, err)
	require.Equal(t, []byte("secret"), value)
	require.Empty(t, diagnostics.String())
}

func TestWindowsPasswordCommandCancellation(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := Command(ctx, "ping -n 30 127.0.0.1 >nul", &bytes.Buffer{})
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.Less(t, time.Since(start), 3*time.Second)
}

func TestWindowsSuspendedProcessCanBeAssignedBeforeResume(t *testing.T) {
	t.Parallel()
	cmd := exec.CommandContext(t.Context(), "cmd.exe", "/D", "/S", "/C", "echo ready")
	var output bytes.Buffer
	cmd.Stdout = &output
	watch, onStartFailure, err := configureProcess(cmd)
	require.NoError(t, err)
	if err := cmd.Start(); err != nil {
		onStartFailure()
		t.Fatal(err)
	}
	stop, err := watch(t.Context(), cmd)
	if err != nil {
		if killErr := cmd.Process.Kill(); killErr != nil {
			t.Logf("kill failed: %v", killErr)
		}
		if waitErr := cmd.Wait(); waitErr != nil {
			t.Logf("wait failed: %v", waitErr)
		}
		t.Fatal(err)
	}
	err = cmd.Wait()
	stop()
	require.NoError(t, err)
	require.Contains(t, output.String(), "ready")
}

func TestWindowsStartFailureClosesJob(t *testing.T) {
	t.Parallel()
	cmd := exec.CommandContext(t.Context(), "definitely-missing-password-program.exe")
	_, onStartFailure, err := configureProcess(cmd)
	require.NoError(t, err)
	require.Error(t, cmd.Start())
	require.NoError(t, onStartFailure())
	require.NoError(t, onStartFailure())
}

func TestWindowsPromptInOwnConsole(t *testing.T) {
	if os.Getenv("SWYS_TEST_WINDOWS_PROMPT_HELPER") == "1" {
		runWindowsPromptHelper(t)
		return
	}
	t.Parallel()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestWindowsPromptInOwnConsole$")
	cmd.Env = append(os.Environ(), "SWYS_TEST_WINDOWS_PROMPT_HELPER=1")
	cmd.SysProcAttr = &windows.SysProcAttr{CreationFlags: windows.CREATE_NEW_CONSOLE}
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, "%s", output)
}

func runWindowsPromptHelper(t *testing.T) {
	t.Helper()
	input, err := openTerminal()
	require.NoError(t, err)
	defer func() {
		if err := input.Close(); err != nil {
			t.Errorf("close console input: %v", err)
		}
	}()
	handle := windows.Handle(input.Fd())
	var originalMode uint32
	require.NoError(t, windows.GetConsoleMode(handle, &originalMode))
	units := append(utf16.Encode([]rune("é😀")), '\r')
	writeInput := windows.NewLazySystemDLL("kernel32.dll").NewProc("WriteConsoleInputW")
	for _, unit := range units {
		record := consoleInputRecord{eventType: 1, keyDown: 1, repeat: 1, char: unit}
		var count uint32
		result, _, callErr := writeInput.Call(uintptr(handle), uintptr(unsafe.Pointer(&record)), 1, uintptr(unsafe.Pointer(&count)))
		require.NotZero(t, result, "write console event: %v", callErr)
		require.Equal(t, uint32(1), count)
	}
	value, err := Prompt(t.Context(), false)
	require.NoError(t, err)
	require.Equal(t, []byte("é😀"), value)
	var restoredMode uint32
	require.NoError(t, windows.GetConsoleMode(handle, &restoredMode))
	require.Equal(t, originalMode, restoredMode)
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	_, err = Prompt(ctx, false)
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.NoError(t, windows.GetConsoleMode(handle, &restoredMode))
	require.Equal(t, originalMode, restoredMode)
}
