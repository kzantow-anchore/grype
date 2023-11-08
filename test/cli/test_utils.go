package cli

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"text/template"
	"time"

	"gopkg.in/yaml.v3"
)

func grypeBinaryLocation(t testing.TB, goOS_goArch ...string) string {
	goOS := runtime.GOOS
	goArch := runtime.GOARCH
	if len(goOS_goArch) > 0 {
		goOS = goOS_goArch[0]
		if len(goOS_goArch) > 1 {
			goArch = goOS_goArch[0]
		}
	}
	return getBinaryLocationByOS(t, "grype", goOS, goArch)
}

func getBinaryLocationByOS(t testing.TB, binaryName, goOS, goArch string) string {
	// note: for amd64 we need to update the snapshot location with the v1 suffix
	// see : https://goreleaser.com/customization/build/#why-is-there-a-_v1-suffix-on-amd64-builds
	archPath := goArch
	if goArch == "amd64" {
		archPath = fmt.Sprintf("%s_v1", archPath)
	}

	bin := ""
	// note: there is a subtle - vs _ difference between these versions
	switch goOS {
	case "windows", "darwin", "linux":
		bin = path.Join(repoRoot(t), fmt.Sprintf("snapshot/%s-build_%s_%s/%s", goOS, goOS, archPath, binaryName))
	default:
		t.Fatalf("unsupported OS: %s", goOS)
		return ""
	}

	// only run on valid bin target
	if bin != "" {
		envName := strings.ToUpper(fmt.Sprintf("%s_BINARY_LOCATION_%s_%s", binaryName, goOS, goArch))
		if os.Getenv(envName) == "" {
			buildBinary(t, binaryName, bin, goOS, goArch)
			err := os.Chmod(binaryName, 0755)
			if err != nil {
				t.Logf("error setting file mode: %s", err)
			}
			// regardless if we have a successful build, don't attempt to keep building
			_ = os.Setenv(envName, bin)
		}
	}

	return bin
}

func buildBinary(t testing.TB, binaryName, outfile, goOS, goArch string) {
	dir := repoRoot(t)

	start := time.Now()

	var stdout, stderr string
	var err error
	switch os.Getenv(strings.ToUpper(binaryName + "_TEST_CLI_BUILD_WITH")) {
	case "goreleaser":
		stdout, stderr, err = buildBinaryWithGoreleaser(dir, goOS, goArch)
	default:
		stdout, stderr, err = buildBinaryWithGo(dir, binaryName, outfile, goOS, goArch)
	}

	took := time.Now().Sub(start).Round(time.Millisecond)
	if err == nil {
		if len(stderr) == 0 {
			t.Logf("binary is up to date: %s in %v", outfile, took)
		} else {
			t.Logf("built binary: %s in %v\naffected paths:\n%s", outfile, took, stderr)
		}
	} else {
		t.Logf("unable to build binary: %s %v\nSTDOUT:\n%s\nSTDERR:\n%s", outfile, err, stdout, stderr)
	}
}

func buildBinaryWithGo(dir, binaryName, outfile, goOS, goArch string) (string, string, error) {
	d := yaml.NewDecoder(strings.NewReader(goreleaserYamlContents(dir)))
	type releaser struct {
		Builds []struct {
			ID      string `yaml:"id"`
			LDFlags string `yaml:"ldflags"`
		} `yaml:"builds"`
	}
	r := releaser{}
	_ = d.Decode(&r)
	ldflags := ""
	for _, b := range r.Builds {
		if b.ID == "linux-build" {
			ldflags = executeTemplate(b.LDFlags, struct {
				Version string
				Commit  string
				Date    string
				Summary string
			}{
				Version: "SNAPSHOT", // should contain "SNAPSHOT" so update checks are skipped
				Commit:  "COMMIT",
				Date:    "DATE",
				Summary: "SUMMARY",
			})
			break
		}
	}

	cmd := exec.Command("go",
		"build",
		"-v",
		"-o", outfile,
		"-trimpath",
		"-ldflags", ldflags,
		fmt.Sprintf("./cmd/%s", binaryName),
	)

	cmd.Dir = dir
	stdout, stderr, err := runCommand(cmd, map[string]string{
		"CGO_ENABLED": "0",
		"GOOS":        goOS,
		"GOARCH":      goArch,
	})
	return stdout, stderr, err
}

func goreleaserYamlContents(dir string) string {
	b, _ := os.ReadFile(path.Join(dir, ".goreleaser.yaml"))
	return string(b)
}

func executeTemplate(tpl string, data any) string {
	t, err := template.New("tpl").Parse(tpl)
	if err != nil {
		return fmt.Sprintf("ERROR: %v", err)
	}
	out := &bytes.Buffer{}
	err = t.Execute(out, data)
	if err != nil {
		return fmt.Sprintf("ERROR: %v", err)
	}
	return out.String()
}

func buildBinaryWithGoreleaser(dir string, goOS, goArch string) (string, string, error) {
	tmpDir := path.Join(dir, ".tmp")

	goreleaserYaml := goreleaserYamlContents(dir)

	// create a config with the dist dir overridden
	tmpGoreleaserYamlFile := path.Join(tmpDir, "goreleaser.yaml")
	_ = os.WriteFile(tmpGoreleaserYamlFile, []byte("dist: snapshot\n"+goreleaserYaml), os.ModePerm)

	cmd := exec.Command(path.Join(tmpDir, "goreleaser"),
		"build",
		"--snapshot",
		"--single-target",
		"--clean",
		"--config", tmpGoreleaserYamlFile,
	)
	cmd.Dir = dir
	stdout, stderr, err := runCommand(cmd, map[string]string{
		"GOOS":   goOS,
		"GOARCH": goArch,
	})
	return stdout, stderr, err
}

func repoRoot(tb testing.TB) string {
	tb.Helper()
	root, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		tb.Fatalf("unable to find repo root dir: %+v", err)
	}
	absRepoRoot, err := filepath.Abs(strings.TrimSpace(string(root)))
	if err != nil {
		tb.Fatal("unable to get abs path to repo root:", err)
	}
	return absRepoRoot
}

func runCommand(cmd *exec.Cmd, env map[string]string) (string, string, error) {
	if env != nil {
		cmd.Env = append(os.Environ(), envMapToSlice(env)...)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	// ignore errors since this may be what the test expects
	err := cmd.Run()

	return stdout.String(), stderr.String(), err
}

func envMapToSlice(env map[string]string) (envList []string) {
	for key, val := range env {
		if key == "" {
			continue
		}
		envList = append(envList, fmt.Sprintf("%s=%s", key, val))
	}
	return
}
