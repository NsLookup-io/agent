package install

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/nslookup-io/agent/internal/protocol"
)

const (
	// DockerSocket is where the Docker Engine API listens, mounted into the agent's container when the customer wants
	// containers reloaded.
	DockerSocket = "/var/run/docker.sock"
	// dockerAPI is the Engine API version asked for: Docker 20.10 and later.
	dockerAPI = "/v1.41"
	// dockerTimeout is the time each container's signal gets.
	dockerTimeout = 10 * time.Second
	// maxDockerAnswer: no more of an answer is read (Docker's errors are one line of JSON).
	maxDockerAnswer = 4 << 10
)

var (
	dockerContainerName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$`)
	// dockerSignals are the only signals sent: the ones web servers and mail servers reload on.
	dockerSignals = []string{"HUP", "USR1", "USR2"}
)

// DockerReload sends a signal to containers through the Docker Engine API on its unix socket, after a folder
// certificate is written (Docker mode): what makes a web server in another container load it again. The socket is
// opt-in, mounted only when the customer wants this: it gives the agent root on the host. Nothing but
// POST /containers/<name>/kill with one of three signals is ever sent.
type DockerReload struct {
	// Containers are the names (or ids) of the containers signalled, in order.
	Containers []string
	// Signal is HUP, USR1 or USR2; "" = HUP.
	Signal string
	// Socket is the Docker socket; "" = DockerSocket.
	Socket string
}

// run signals every container, each even when one before it failed, says how it went as one hook_ran step, and
// whether it failed. No socket mounted: the step says to reload them by hand and fails nothing (the customer chose not
// to mount it). Docker refusing one, or not answering: the step fails with Docker's message.
func (r *DockerReload) run(ctx context.Context, o *Outcome) (failed bool) {
	signal := cmp.Or(r.Signal, "HUP")
	if !slices.Contains(dockerSignals, signal) {
		o.Fail(protocol.StepHookRan, fmt.Sprintf("the agent sends HUP, USR1 or USR2, not %s", signal))
		return true
	}
	for _, name := range r.Containers {
		if !dockerContainerName.MatchString(name) {
			o.Fail(protocol.StepHookRan, fmt.Sprintf("%q is not a container name", name))
			return true
		}
	}
	names := strings.Join(r.Containers, ", ")
	socket := cmp.Or(r.Socket, DockerSocket)
	if _, err := os.Stat(socket); errors.Is(err, fs.ErrNotExist) {
		o.Step(protocol.StepHookRan, false, "no Docker socket mounted; reload "+names+" yourself")
		return false
	}
	client := &http.Client{
		Timeout: dockerTimeout,
		Transport: &http.Transport{
			// The socket only: never a proxy of the environment.
			Proxy: nil,
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", socket)
			},
			DisableKeepAlives: true,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	defer client.CloseIdleConnections()
	var refused, sent []string
	for _, name := range r.Containers {
		if err := kill(ctx, client, name, signal); err != nil {
			refused = append(refused, name+": "+err.Error())
		} else {
			sent = append(sent, name)
		}
	}
	said := refused
	if len(sent) > 0 {
		said = append(said, "sent "+signal+" to "+strings.Join(sent, ", "))
	}
	if len(refused) > 0 {
		o.Fail(protocol.StepHookRan, strings.Join(said, "; "))
		return true
	}
	o.OK(protocol.StepHookRan, strings.Join(said, "; "))
	return false
}

// kill asks Docker to send signal to the container name.
func kill(ctx context.Context, client *http.Client, name, signal string) error {
	u := "http://docker" + dockerAPI + "/containers/" + url.PathEscape(name) + "/kill?" + url.Values{"signal": {signal}}.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		// The URL is ours and says nothing: only why the socket did not answer.
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return fmt.Errorf("the Docker socket did not answer: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxDockerAnswer))
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	var answer struct {
		Message string `json:"message"`
	}
	if json.Unmarshal(body, &answer) != nil || answer.Message == "" {
		answer.Message = strings.TrimSpace(string(body))
	}
	return fmt.Errorf("Docker answered %d: %s", resp.StatusCode, protocol.Clip(cmp.Or(answer.Message, http.StatusText(resp.StatusCode)), 300))
}
