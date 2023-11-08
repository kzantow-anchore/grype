package cli

import (
	"bytes"
	"io"
	"os/exec"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/anchore/stereoscope/pkg/imagetest"
)

func getFixtureImage(tb testing.TB, fixtureImageName string) string {
	tb.Helper()

	imagetest.GetFixtureImage(tb, "docker-archive", fixtureImageName)
	return imagetest.GetFixtureImageTarPath(tb, fixtureImageName)
}

func getGrypeCommand(tb testing.TB, args ...string) *exec.Cmd {
	tb.Helper()

	return exec.Command(
		grypeBinaryLocation(tb),
		append(
			[]string{"-c", "../grype-test-config.yaml"},
			args...,
		)...,
	)
}

func getDockerRunCommand(tb testing.TB, args ...string) *exec.Cmd {
	tb.Helper()

	return exec.Command(
		"docker",
		append(
			[]string{"run"},
			args...,
		)...,
	)
}

func runGrype(tb testing.TB, env map[string]string, args ...string) (*exec.Cmd, string, string) {
	tb.Helper()

	cmd := getGrypeCommand(tb, args...)
	if env == nil {
		env = make(map[string]string)
	}

	// we should not have tests reaching out for app update checks
	env["GRYPE_CHECK_FOR_APP_UPDATE"] = "false"

	stdout, stderr, _ := runCommand(cmd, env)
	return cmd, stdout, stderr
}

func attachFileToCommandStdin(tb testing.TB, file io.Reader, command *exec.Cmd) {
	tb.Helper()

	b, err := io.ReadAll(file)
	require.NoError(tb, err)
	command.Stdin = bytes.NewReader(b)
}

func assertCommandExecutionSuccess(t testing.TB, cmd *exec.Cmd) {
	_, err := cmd.CombinedOutput()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			t.Fatal(exitErr)
		}

		t.Fatalf("unable to run command %q: %v", cmd, err)
	}
}

func testWithTimeout(t *testing.T, name string, timeout time.Duration, test func(*testing.T)) {
	done := make(chan bool)
	go func() {
		t.Run(name, test)
		done <- true
	}()

	select {
	case <-time.After(timeout):
		t.Fatal("test timed out")
	case <-done:
	}
}
