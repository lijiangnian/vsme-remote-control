//go:build darwin

package main

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// Run on a real Mac. The BSD script utility supplies a real kernel PTY, while
// the second invocation uses /dev/null. Neither starts a maintenance agent.
func TestMacKernelTerminalDetection(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, attached := range []bool{true, false} {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		var cmd *exec.Cmd
		if attached {
			cmd = exec.CommandContext(ctx, "/usr/bin/script", "-q", "/dev/null", self, "-test.v", "-test.run=^TestMacTerminalProbeChild$")
		} else {
			cmd = exec.CommandContext(ctx, self, "-test.v", "-test.run=^TestMacTerminalProbeChild$")
		}
		expected := "false"
		if attached {
			expected = "true"
		}
		cmd.Env = append(os.Environ(), "VSME_TEST_TERMINAL="+expected)
		reader, writer, err := os.Pipe()
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		if attached {
			cmd.Stdin = reader
		}
		out, runErr := cmd.CombinedOutput()
		reader.Close()
		writer.Close()
		cancel()
		if runErr != nil || !strings.Contains(string(out), "MAC_TERMINAL_PROBE=PASS") {
			t.Fatalf("attached=%v: %v\n%s", attached, runErr, out)
		}
	}
}

func TestMacTerminalProbeChild(t *testing.T) {
	expected := os.Getenv("VSME_TEST_TERMINAL")
	if expected == "" {
		t.Skip("subprocess-only terminal probe")
	}
	if terminalAttached() != (expected == "true") {
		t.Fatal("kernel terminal detection disagrees with launch mode")
	}
	t.Log("MAC_TERMINAL_PROBE=PASS")
}
