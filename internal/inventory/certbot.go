package inventory

import (
	"io/fs"
	"strings"
)

const (
	certbotLive    = "/etc/letsencrypt/live/"
	certbotRenewal = "/etc/letsencrypt/renewal/"
	// maxCertbotName is the server's limit for a certbot name.
	maxCertbotName = 255
)

// certbotName is the certbot certificate name of a certificate file directly under /etc/letsencrypt/live/<name>/, when
// certbot renews it (/etc/letsencrypt/renewal/<name>.conf exists); "" otherwise.
func certbotName(fsys fs.FS, certPath string) string {
	rest, ok := strings.CutPrefix(certPath, certbotLive)
	if !ok {
		return ""
	}
	name, file, ok := strings.Cut(rest, "/")
	if !ok || name == "" || name == "." || name == ".." || len(name) > maxCertbotName || file == "" || strings.Contains(file, "/") {
		return ""
	}
	if !isFile(fsys, certbotRenewal+name+".conf") {
		return ""
	}
	return name
}
