#!/bin/sh
# Checks the Helm chart in deploy/helm/agent: helm lint, then what helm template renders. The agent may only read
# Ingresses (get, list, watch) and read and write Secrets (get, create, update, patch): cluster-wide by default, else
# one Role per listed namespace plus a Role for its identity Secret in its own namespace. The join code goes only into a
# Secret, and the Deployment runs one non-root replica with a read-only root file system.
#
# Needs helm 3 and POSIX tools only. Run from anywhere: sh scripts/check-chart.sh
set -eu

chart=$(cd "$(dirname "$0")/.." && pwd)/deploy/helm/agent
release=nslookup-agent
ns=agents
code=nsj_chartcheck0123456789abcdef

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
trap 'exit 1' INT TERM

failures=0
fail() {
	printf 'FAIL: %s\n' "$*" >&2
	failures=$((failures + 1))
}

if [ ! -f "$chart/Chart.yaml" ]; then
	printf 'FAIL: there is no chart at %s\n' "$chart" >&2
	exit 1
fi

# render FILE [helm template flags]: the chart's manifests, in the namespace $ns.
render() {
	out=$1
	shift
	if ! helm template "$release" "$chart" --namespace "$ns" "$@" >"$out" 2>"$tmp/helm-error"; then
		fail "helm template $*: $(cat "$tmp/helm-error")"
		: >"$out"
	fi
}

# docs KIND [NAMESPACE] <manifests: the documents of that kind (in that namespace), each followed by a line "---".
docs() {
	awk -v kind="$1" -v ns="${2-}" '
		function flush() {
			if (doc != "" && k == kind && (ns == "" || n == ns)) printf "%s---\n", doc
			doc = ""; k = ""; n = ""
		}
		/^---$/ { flush(); next }
		{ doc = doc $0 "\n" }
		/^kind: / { k = substr($0, 7) }
		/^  namespace: / { if (n == "") n = substr($0, 14) }
		END { flush() }'
}

# count KIND [NAMESPACE] <manifests: how many documents of that kind there are.
count() {
	docs "$@" | grep -c '^---$' || true
}

# block LINE <manifest: the lines nested under the first line that is exactly LINE (deeper indented), as they are.
block() {
	awk -v key="$1" '
		found && $0 !~ /^ *$/ { match($0, /^ */); if (RLENGTH <= ind) exit }
		found { print }
		!found && $0 == key { found = 1; match($0, /^ */); ind = RLENGTH }'
}

# same WHAT EXPECTED-FILE ACTUAL-FILE: the two are the same text, else the difference is shown.
same() {
	if ! diff -u "$2" "$3" >"$tmp/diff"; then
		fail "$1:"
		cat "$tmp/diff" >&2
	fi
}

# expect FILE TEXT: FILE holds TEXT (and a final newline).
expect() {
	printf '%s\n' "$2" >"$1"
}

# What the agent may do, as a ClusterRole or as a Role in each namespace it may write in.
expect "$tmp/agent-rules" '  - apiGroups: ["networking.k8s.io"]
    resources: ["ingresses"]
    verbs: ["get", "list", "watch"]
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["get", "create", "update", "patch"]'

# Its identity Secret in its own namespace, when that namespace is not one it may write in: read, and updated when the
# server rolls its signing key over. RBAC cannot limit create to a name (the name is not known when create is
# authorized), so create is a rule of its own.
expect "$tmp/identity-rules" '  - apiGroups: [""]
    resources: ["secrets"]
    resourceNames: ["nslookup-agent-identity"]
    verbs: ["get", "update"]
  - apiGroups: [""]
    resources: ["secrets"]
    verbs: ["create"]'

# rules KIND NAMESPACE MANIFESTS WHAT EXPECTED: the rules of the one document of that kind in that namespace.
rules() {
	docs "$1" "$2" <"$3" >"$tmp/doc"
	if [ "$(grep -c '^---$' "$tmp/doc")" != 1 ]; then
		fail "$4: want one $1${2:+ in $2}, got $(grep -c '^---$' "$tmp/doc")"
		return
	fi
	awk '/^rules:$/ { on = 1; next } on && (/^---$/ || /^[^ ]/) { on = 0 } on' "$tmp/doc" >"$tmp/rules"
	same "$4" "$5" "$tmp/rules"
}

# binding KIND NAMESPACE MANIFESTS ROLE-KIND WHAT: the one binding of that kind there gives the agent's service account
# the agent's own role, and nothing else.
binding() {
	docs "$1" "$2" <"$3" >"$tmp/doc"
	if [ "$(grep -c '^---$' "$tmp/doc")" != 1 ]; then
		fail "$5: want one $1${2:+ in $2}, got $(grep -c '^---$' "$tmp/doc")"
		return
	fi
	role=$(awk '/^metadata:$/ { m = 1; next } m && /^  name: / { print substr($0, 9); exit }' "$tmp/doc")
	expect "$tmp/want" "roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: $4
  name: $role
subjects:
  - kind: ServiceAccount
    name: $release
    namespace: $ns"
	awk '/^roleRef:$/ { on = 1 } on && /^---$/ { on = 0 } on' "$tmp/doc" >"$tmp/got"
	same "$5" "$tmp/want" "$tmp/got"
}

# no_ingress_writes MANIFESTS WHAT: no rule lets the agent change an Ingress, and no rule uses a wildcard.
no_ingress_writes() {
	if ! awk '
		/^ *(- )?resources:/ { ingress = ($0 ~ /ingresses/) }
		/^ *verbs:/ && ingress {
			v = $0
			sub(/^ *verbs:/, "", v)
			gsub(/"get"|"list"|"watch"|[][ ,]/, "", v)
			if (v != "") { print "  " $0; bad = 1 }
		}
		/^ *(- )?(apiGroups|resources|verbs|resourceNames):.*\*/ { print "  " $0; bad = 1 }
		END { exit bad }' "$1" >"$tmp/bad"; then
		fail "$2: a rule changes Ingresses or uses a wildcard:"
		cat "$tmp/bad" >&2
	fi
}

# deployment MANIFESTS: the one Deployment of the release.
deployment() {
	docs Deployment "$ns" <"$1" >"$tmp/deployment"
	if [ "$(grep -c '^---$' "$tmp/deployment")" != 1 ]; then
		fail "want one Deployment in $ns, got $(grep -c '^---$' "$tmp/deployment")"
	fi
}

# env_is MANIFESTS WHAT EXPECTED: the agent container's environment.
env_is() {
	deployment "$1"
	block '          env:' <"$tmp/deployment" >"$tmp/env"
	same "$2" "$3" "$tmp/env"
}

# code_only_in_a_secret MANIFESTS WHAT: the join code is in exactly one document, a Secret.
code_only_in_a_secret() {
	if ! awk -v code="$code" '
		function flush() {
			if (has) { n++; if (k != "Secret") { print "  in a " k; bad = 1 } }
			has = 0; k = ""
		}
		/^---$/ { flush(); next }
		/^kind: / { k = substr($0, 7) }
		index($0, code) { has = 1 }
		END { flush(); if (n != 1) { print "  in " n " documents"; bad = 1 }; exit bad }' "$1" >"$tmp/bad"; then
		fail "$2: the join code must be in one Secret only:"
		cat "$tmp/bad" >&2
	fi
}

## helm lint

if ! helm lint --strict "$chart" >"$tmp/lint" 2>&1; then
	fail "helm lint:"
	cat "$tmp/lint" >&2
fi
if ! helm lint --strict "$chart" --set-string joinCode="$code" --set "namespaces={a,b}" >"$tmp/lint" 2>&1; then
	fail "helm lint with a join code and namespaces:"
	cat "$tmp/lint" >&2
fi

## Every namespace (the default): a ClusterRole with exactly the agent's rules.

render "$tmp/default"
[ "$(count ClusterRole <"$tmp/default")" = 1 ] || fail "default: want one ClusterRole, got $(count ClusterRole <"$tmp/default")"
rules ClusterRole "" "$tmp/default" "default: the ClusterRole's rules" "$tmp/agent-rules"
binding ClusterRoleBinding "" "$tmp/default" ClusterRole "default: the ClusterRoleBinding"
[ "$(count Role <"$tmp/default")" = 0 ] || fail "default: want no Role, got $(count Role <"$tmp/default")"
[ "$(count RoleBinding <"$tmp/default")" = 0 ] || fail "default: want no RoleBinding, got $(count RoleBinding <"$tmp/default")"
[ "$(count ServiceAccount "$ns" <"$tmp/default")" = 1 ] || fail "default: want one ServiceAccount in $ns"
[ "$(count Secret <"$tmp/default")" = 0 ] || fail "default: want no Secret without a join code"
no_ingress_writes "$tmp/default" default

## Only these namespaces: one Role each, the identity Role in the release namespace, and no ClusterRole.

render "$tmp/limited" --set "namespaces={a,b}"
[ "$(count ClusterRole <"$tmp/limited")" = 0 ] || fail "namespaces a,b: want no ClusterRole"
[ "$(count ClusterRoleBinding <"$tmp/limited")" = 0 ] || fail "namespaces a,b: want no ClusterRoleBinding"
[ "$(count Role <"$tmp/limited")" = 3 ] || fail "namespaces a,b: want 3 Roles (a, b and the identity Role), got $(count Role <"$tmp/limited")"
[ "$(count RoleBinding <"$tmp/limited")" = 3 ] || fail "namespaces a,b: want 3 RoleBindings, got $(count RoleBinding <"$tmp/limited")"
for n in a b; do
	rules Role "$n" "$tmp/limited" "namespaces a,b: the Role in $n" "$tmp/agent-rules"
	binding RoleBinding "$n" "$tmp/limited" Role "namespaces a,b: the RoleBinding in $n"
done
rules Role "$ns" "$tmp/limited" "namespaces a,b: the identity Role in $ns" "$tmp/identity-rules"
binding RoleBinding "$ns" "$tmp/limited" Role "namespaces a,b: the identity RoleBinding in $ns"
no_ingress_writes "$tmp/limited" "namespaces a,b"

# The release namespace among them: its Role already covers the identity Secret. A name given twice is one Role.
render "$tmp/own" --set "namespaces={a,$ns,a}"
[ "$(count Role <"$tmp/own")" = 2 ] || fail "namespaces a,$ns,a: want 2 Roles, got $(count Role <"$tmp/own")"
rules Role "$ns" "$tmp/own" "namespaces a,$ns,a: the Role in $ns" "$tmp/agent-rules"
rules Role a "$tmp/own" "namespaces a,$ns,a: the Role in a" "$tmp/agent-rules"
no_ingress_writes "$tmp/own" "namespaces a,$ns,a"

# A namespace that is not a namespace name is refused.
if helm template "$release" "$chart" --namespace "$ns" --set "namespaces={Web}" >/dev/null 2>&1; then
	fail "namespaces Web: helm template must fail"
fi

## The Deployment.

deployment "$tmp/default"
grep -qxF '  replicas: 1' "$tmp/deployment" || fail "the Deployment must have replicas: 1"
expect "$tmp/want" '    type: Recreate'
block '  strategy:' <"$tmp/deployment" >"$tmp/got"
same "the Deployment's strategy" "$tmp/want" "$tmp/got"
grep -qxF "      serviceAccountName: $release" "$tmp/deployment" || fail "the Deployment must run as the service account $release"
grep -qxF '          image: "ghcr.io/nslookup-io/agent:1.0.0"' "$tmp/deployment" || fail "the image must default to the chart's appVersion"
grep -qxF '          args: ["run", "--mode=kubernetes"]' "$tmp/deployment" || fail "the agent must run with --mode=kubernetes"

expect "$tmp/want" '        runAsNonRoot: true
        runAsUser: 65532
        runAsGroup: 65532
        seccompProfile:
          type: RuntimeDefault'
block '      securityContext:' <"$tmp/deployment" >"$tmp/got"
same "the pod's securityContext" "$tmp/want" "$tmp/got"

expect "$tmp/want" '            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            runAsNonRoot: true
            runAsUser: 65532
            runAsGroup: 65532
            capabilities:
              drop: ["ALL"]
            seccompProfile:
              type: RuntimeDefault'
block '          securityContext:' <"$tmp/deployment" >"$tmp/got"
same "the container's securityContext" "$tmp/want" "$tmp/got"

expect "$tmp/want" '            - name: state
              mountPath: /var/lib/nslookup-agent'
block '          volumeMounts:' <"$tmp/deployment" >"$tmp/got"
same "the container's volumeMounts" "$tmp/want" "$tmp/got"
expect "$tmp/want" '        - name: state
          emptyDir: {}'
block '      volumes:' <"$tmp/deployment" >"$tmp/got"
same "the pod's volumes" "$tmp/want" "$tmp/got"

# Without a join code: its namespace and its mode only.
expect "$tmp/want" '            - name: POD_NAMESPACE
              valueFrom:
                fieldRef:
                  fieldPath: metadata.namespace
            - name: NSL_MODE
              value: kubernetes'
env_is "$tmp/default" "the environment without values" "$tmp/want"

## The join code: only in a Secret, which the Deployment reads.

render "$tmp/join" --set-string joinCode="$code" --set-string "name=web 1" \
	--set-string server=https://agents.example.test --set "namespaces={a,b}"
code_only_in_a_secret "$tmp/join" "joinCode"
[ "$(count Secret "$ns" <"$tmp/join")" = 1 ] || fail "joinCode: want one Secret in $ns"
expect "$tmp/want" '            - name: POD_NAMESPACE
              valueFrom:
                fieldRef:
                  fieldPath: metadata.namespace
            - name: NSL_MODE
              value: kubernetes
            - name: NSL_JOIN
              valueFrom:
                secretKeyRef:
                  name: nslookup-agent-join
                  key: joinCode
            - name: NSL_NAME
              value: "web 1"
            - name: NSL_SERVER
              value: "https://agents.example.test"
            - name: NSL_NAMESPACES
              value: "a,b"'
env_is "$tmp/join" "the environment with every value" "$tmp/want"

# A Secret of the customer's own: no Secret of ours, and the code given as well goes nowhere.
render "$tmp/existing" --set existingJoinSecret=my-join --set-string joinCode="$code"
[ "$(count Secret <"$tmp/existing")" = 0 ] || fail "existingJoinSecret: want no Secret"
if grep -q "$code" "$tmp/existing"; then
	fail "existingJoinSecret: the join code must not be rendered"
fi
expect "$tmp/want" '            - name: POD_NAMESPACE
              valueFrom:
                fieldRef:
                  fieldPath: metadata.namespace
            - name: NSL_MODE
              value: kubernetes
            - name: NSL_JOIN
              valueFrom:
                secretKeyRef:
                  name: my-join
                  key: joinCode
                  optional: true'
env_is "$tmp/existing" "the environment with existingJoinSecret" "$tmp/want"

## Annotations: off by default (no variable), on with annotations.enabled, and a release whose old values have no
## annotations key (helm upgrade --reuse-values) still renders.

if grep -q NSL_ANNOTATIONS "$tmp/default"; then
	fail "default: NSL_ANNOTATIONS must not be set"
fi
render "$tmp/annotations" --set annotations.enabled=true
expect "$tmp/want" '            - name: POD_NAMESPACE
              valueFrom:
                fieldRef:
                  fieldPath: metadata.namespace
            - name: NSL_MODE
              value: kubernetes
            - name: NSL_ANNOTATIONS
              value: "true"'
env_is "$tmp/annotations" "the environment with annotations.enabled" "$tmp/want"
render "$tmp/annotations-off" --set annotations.enabled=false
if grep -q NSL_ANNOTATIONS "$tmp/annotations-off"; then
	fail "annotations.enabled=false: NSL_ANNOTATIONS must not be set"
fi
# A string counts as what it says, and anything that is not true or false is refused with a clear message.
render "$tmp/annotations-str-off" --set-string annotations.enabled=false
if grep -q NSL_ANNOTATIONS "$tmp/annotations-str-off"; then
	fail 'annotations.enabled="false" (a string): NSL_ANNOTATIONS must not be set'
fi
render "$tmp/annotations-str-on" --set-string annotations.enabled=true
env_is "$tmp/annotations-str-on" 'the environment with annotations.enabled="true" (a string)' "$tmp/want"
refused() {
	what=$1
	want_text=$2
	shift 2
	if helm template "$release" "$chart" --namespace "$ns" "$@" >/dev/null 2>"$tmp/helm-error"; then
		fail "$what: helm template must fail"
	elif ! grep -qF "$want_text" "$tmp/helm-error"; then
		fail "$what: the error must say '$want_text', got: $(cat "$tmp/helm-error")"
	fi
}
refused "annotations=true" "annotations is a map" --set annotations=true
refused "annotations.enabled=yes" "annotations.enabled is true or false" --set-string annotations.enabled=yes
refused "annotations.enabled=1" "annotations.enabled is true or false" --set annotations.enabled=1
# Turning it on changes the environment only: the rules are the ones of the default render.
render "$tmp/annotations-rules" --set annotations.enabled=true
rules ClusterRole "" "$tmp/annotations-rules" "annotations.enabled: the ClusterRole's rules" "$tmp/agent-rules"
docs ClusterRole <"$tmp/default" >"$tmp/a"
docs ClusterRole <"$tmp/annotations-rules" >"$tmp/b"
same "annotations.enabled: the ClusterRole must be the default one" "$tmp/a" "$tmp/b"
render "$tmp/annotations-limited" --set annotations.enabled=true --set "namespaces={a,b}"
rules Role a "$tmp/annotations-limited" "annotations.enabled, namespaces a,b: the Role in a" "$tmp/agent-rules"
rules Role "$ns" "$tmp/annotations-limited" "annotations.enabled, namespaces a,b: the identity Role" "$tmp/identity-rules"
no_ingress_writes "$tmp/annotations-rules" "annotations.enabled"
# An old release's values have no annotations key: null drops the chart's own default, as --reuse-values does.
printf 'annotations: null\n' >"$tmp/null-values.yaml"
render "$tmp/null" -f "$tmp/null-values.yaml"
if grep -q NSL_ANNOTATIONS "$tmp/null"; then
	fail "annotations: null: NSL_ANNOTATIONS must not be set"
fi

## Nothing anywhere names the identity Secret except the identity Role.

for f in "$tmp/default" "$tmp/limited" "$tmp/join" "$tmp/existing"; do
	if [ "$(docs Secret <"$f" | grep -c 'nslookup-agent-identity' || true)" != 0 ]; then
		fail "the chart must not render the identity Secret (the agent creates it)"
	fi
done

if [ "$failures" -gt 0 ]; then
	printf '%d check(s) failed\n' "$failures" >&2
	exit 1
fi
echo "chart checks passed"
