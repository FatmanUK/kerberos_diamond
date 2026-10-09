package golden

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// TLSClientImage is the second, clearly-labelled image: Kerberos 5
// built --with-tls-impl=openssl.
//
// **It is not the oracle and nothing is compared against it.** It is
// a client-side fixture for one test, and the reasoning for the
// narrowing of BOOTSTRAP.md section 3.3 that allows it is in
// deploy/golden/Containerfile.krb5-tls.
const TLSClientImage = "localhost/krb5-tls-client"

// TLSClient is a running container holding a TLS-capable Kerberos 5
// client.
//
// It serves no realm and has no entrypoint of its own: the test
// writes a client configuration into it and runs kinit. Giving it a
// KDC to run would invite somebody to compare against it, which is
// exactly what it must not be used for.
type TLSClient struct {
	name string
}

// StartTLSClient runs the container, or reports that the image is
// absent.
//
// Absent is a skip rather than a failure, like the oracle's -- but
// the message names the target, because this image is built by a
// different one and `make golden-build' does not produce it.
func StartTLSClient(
	ctx context.Context,
) (*TLSClient, error) {
	if exec.Command("podman", "image", "exists",
		TLSClientImage).Run() != nil {
		return nil, fmt.Errorf("%s is not built; "+
			"run 'make golden-build-tls'",
			TLSClientImage)
	}
	port, err := freePort()
	if err != nil {
		return nil, err
	}
	// Nothing is published -- this container only makes outbound
	// connections -- so the port is borrowed purely to name the
	// container uniquely, which is how the oracle names its own.
	name := fmt.Sprintf("krb5tls-%d", port)
	run := exec.CommandContext(ctx, "podman", "run",
		"--rm", "-d", "--name", name,
		"--label", oracleLabel,
		"--add-host",
		"host.containers.internal:host-gateway",
		TLSClientImage,
	)
	if out, err := run.CombinedOutput(); err != nil {
		return nil, fmt.Errorf(
			"starting the TLS client: %v: %s", err, out)
	}
	return &TLSClient{name: name}, nil
}

// Close removes the container.
func (c *TLSClient) Close() {
	_ = exec.Command("podman", "rm", "-f", c.name).Run()
}

// WriteFile puts a file inside the container, the same way the
// oracle's helper does: through the shell rather than `podman cp',
// because the content is generated and never on disk here.
func (c *TLSClient) WriteFile(
	ctx context.Context,
	path, content string,
) error {
	cmd := exec.CommandContext(ctx, "podman", "exec", "-i",
		c.name, "sh", "-c",
		"mkdir -p \"$(dirname "+path+")\" && cat > "+path)
	cmd.Stdin = strings.NewReader(content)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("writing %s: %v: %s", path, err,
			out)
	}
	return nil
}

// Exec runs a command inside the container with an environment,
// returning its combined output.
func (c *TLSClient) Exec(
	ctx context.Context,
	env []string,
	stdin string,
	args ...string,
) (string, error) {
	full := []string{"exec", "-i"}
	for _, e := range env {
		full = append(full, "-e", e)
	}
	full = append(full, c.name)
	full = append(full, args...)
	cmd := exec.CommandContext(ctx, "podman", full...)
	cmd.Stdin = strings.NewReader(stdin)
	out, err := cmd.CombinedOutput()
	return string(out), err
}
