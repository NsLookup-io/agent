package kube

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/nslookup-io/agent/internal/version"
)

// serviceAccountNamespace is where Kubernetes tells a pod its namespace.
const serviceAccountNamespace = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"

// Connect is the client of the cluster the agent runs in, with the pod's service account, and the agent's own
// namespace (POD_NAMESPACE, else the service account's). Run outside the cluster with KUBECONFIG set, it is the client
// of that file's current context, and the namespace POD_NAMESPACE or the context's.
func Connect(getenv func(string) string) (kubernetes.Interface, string, error) {
	var cfg *rest.Config
	var ns string
	if paths := getenv("KUBECONFIG"); paths != "" {
		cc := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
			&clientcmd.ClientConfigLoadingRules{Precedence: filepath.SplitList(paths)}, &clientcmd.ConfigOverrides{})
		var err error
		if cfg, err = cc.ClientConfig(); err != nil {
			return nil, "", fmt.Errorf("KUBECONFIG: %w", err)
		}
		if ns = getenv("POD_NAMESPACE"); ns == "" {
			if ns, _, err = cc.Namespace(); err != nil {
				return nil, "", fmt.Errorf("KUBECONFIG: %w", err)
			}
		}
	} else {
		var err error
		if cfg, err = rest.InClusterConfig(); err != nil {
			return nil, "", fmt.Errorf("%w (outside a cluster, set KUBECONFIG)", err)
		}
		if ns, err = ownNamespace(getenv, serviceAccountNamespace); err != nil {
			return nil, "", err
		}
	}
	if errs := validation.IsDNS1123Label(ns); len(errs) > 0 {
		return nil, "", fmt.Errorf("%q is not a namespace name", ns)
	}
	cfg.UserAgent = "nslookup-agent/" + version.Version
	cfg.Timeout = apiTimeout
	// A read gets one secret per site (up to 500): client-go's default of 5 requests a second would take 100 s.
	cfg.QPS, cfg.Burst = 20, 40
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, "", err
	}
	return cs, ns, nil
}

// ownNamespace is the agent's namespace in the cluster: POD_NAMESPACE (the chart sets it from the downward API), else
// the service account's namespace file.
func ownNamespace(getenv func(string) string, file string) (string, error) {
	ns := strings.TrimSpace(getenv("POD_NAMESPACE"))
	if ns == "" {
		data, err := os.ReadFile(file)
		if err != nil {
			return "", errors.New("the agent's namespace is not known: set POD_NAMESPACE")
		}
		ns = strings.TrimSpace(string(data))
	}
	if errs := validation.IsDNS1123Label(ns); len(errs) > 0 {
		return "", fmt.Errorf("%q is not a namespace name", ns)
	}
	return ns, nil
}
