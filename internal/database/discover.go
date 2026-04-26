// Package database — discover.go.
//
// Host scan for database engine instances reachable from the agent. Three
// passes run sequentially: systemd unit listing, docker container listing,
// then a TCP fallback for the canonical engine ports. Discovery never reads
// or extracts credentials — explicit user consent (a Connect call carrying
// username/password, or an opt-in cred-extraction op in a later PR) is
// always required before the agent stores creds in the vault.
//
// Discovery is best-effort: a missing systemctl, docker daemon, or closed
// port is normal and is silently skipped. Each candidate the agent does
// surface is shaped by what the wire (DatabaseDiscoveryCandidate) requires.
package database

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	pb "github.com/cloudnan-tech/cloudnan-agent/proto/agent"
)

const (
	defaultMySQLPort    uint32 = 3306
	defaultPostgresPort uint32 = 5432

	mysqlSocket    = "/var/run/mysqld/mysqld.sock"
	postgresSocket = "/var/run/postgresql/.s.PGSQL.5432"

	portScanTimeout       = 200 * time.Millisecond
	versionExecTimeout    = 2 * time.Second
	systemctlExecTimeout  = 5 * time.Second
	dockerPSExecTimeout   = 5 * time.Second
	dockerSockPath        = "/var/run/docker.sock"
	alternateDockerSock   = "/run/docker.sock"
	systemctlListUnitsCmd = "systemctl"
)

// Discover scans the host for DB instances and returns candidates filtered
// by req.Engines (empty == all engines).
func Discover(ctx context.Context, req *pb.DatabaseDiscoverRequest) (*pb.DatabaseDiscoverResponse, error) {
	if req == nil {
		req = &pb.DatabaseDiscoverRequest{}
	}
	want := engineFilter(req.GetEngines())

	var candidates []*pb.DatabaseDiscoveryCandidate

	// (A) systemd
	if sd, err := scanSystemd(ctx); err == nil {
		candidates = append(candidates, sd...)
	}
	// (B) docker
	if dk, err := scanDocker(ctx); err == nil {
		candidates = append(candidates, dk...)
	}
	// (C) port scan fallback
	candidates = append(candidates, scanPorts(ctx, candidates)...)

	if want != nil {
		filtered := candidates[:0]
		for _, c := range candidates {
			if want[c.GetEngine()] {
				filtered = append(filtered, c)
			}
		}
		candidates = filtered
	}

	return &pb.DatabaseDiscoverResponse{Candidates: candidates}, nil
}

func engineFilter(engines []pb.DatabaseEngine) map[pb.DatabaseEngine]bool {
	if len(engines) == 0 {
		return nil
	}
	m := make(map[pb.DatabaseEngine]bool, len(engines))
	for _, e := range engines {
		m[e] = true
	}
	return m
}

// ---------- systemd ----------

// systemdMatch maps a unit name to an engine. Suffix wildcards (e.g.
// "postgresql@*-main.service") are matched in matchSystemdEngine.
var systemdEngineNames = map[string]pb.DatabaseEngine{
	"mysql.service":      pb.DatabaseEngine_DATABASE_ENGINE_MYSQL,
	"mysqld.service":     pb.DatabaseEngine_DATABASE_ENGINE_MYSQL,
	"mariadb.service":    pb.DatabaseEngine_DATABASE_ENGINE_MARIADB,
	"postgresql.service": pb.DatabaseEngine_DATABASE_ENGINE_POSTGRESQL,
}

var (
	mysqlInstanceRe    = regexp.MustCompile(`^mysql@.+\.service$`)
	mariadbInstanceRe  = regexp.MustCompile(`^mariadb@.+\.service$`)
	postgresInstanceRe = regexp.MustCompile(`^postgresql@.+\.service$`)
)

func matchSystemdEngine(unit string) (pb.DatabaseEngine, bool) {
	if e, ok := systemdEngineNames[unit]; ok {
		return e, true
	}
	switch {
	case mysqlInstanceRe.MatchString(unit):
		return pb.DatabaseEngine_DATABASE_ENGINE_MYSQL, true
	case mariadbInstanceRe.MatchString(unit):
		return pb.DatabaseEngine_DATABASE_ENGINE_MARIADB, true
	case postgresInstanceRe.MatchString(unit):
		return pb.DatabaseEngine_DATABASE_ENGINE_POSTGRESQL, true
	}
	return pb.DatabaseEngine_DATABASE_ENGINE_UNSPECIFIED, false
}

func scanSystemd(ctx context.Context) ([]*pb.DatabaseDiscoveryCandidate, error) {
	if _, err := exec.LookPath(systemctlListUnitsCmd); err != nil {
		return nil, err
	}
	cctx, cancel := context.WithTimeout(ctx, systemctlExecTimeout)
	defer cancel()
	cmd := exec.CommandContext(cctx, systemctlListUnitsCmd,
		"list-units", "--type=service", "--no-legend", "--state=loaded", "--plain")
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	var results []*pb.DatabaseDiscoveryCandidate
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		// systemctl --plain layout: UNIT LOAD ACTIVE SUB DESCRIPTION...
		fields := strings.Fields(line)
		if len(fields) < 1 {
			continue
		}
		unit := fields[0]
		engine, ok := matchSystemdEngine(unit)
		if !ok {
			continue
		}
		c := &pb.DatabaseDiscoveryCandidate{
			Engine:                   engine,
			DiscoveryMethod:          "systemd",
			SystemdUnit:              unit,
			DisplayName:              fmt.Sprintf("%s (%s)", engineLabel(engine), unit),
			Connection:               defaultLocalConnection(engine),
			Version:                  bestEffortLocalVersion(ctx, engine),
			CredentialsAutoExtracted: false,
			CredentialsSource:        "",
		}
		results = append(results, c)
	}
	return results, nil
}

func defaultLocalConnection(engine pb.DatabaseEngine) *pb.DatabaseConnection {
	conn := &pb.DatabaseConnection{Host: "127.0.0.1"}
	switch engine {
	case pb.DatabaseEngine_DATABASE_ENGINE_MYSQL,
		pb.DatabaseEngine_DATABASE_ENGINE_MARIADB:
		conn.Port = defaultMySQLPort
		if fileExists(mysqlSocket) {
			conn.SocketPath = mysqlSocket
		}
	case pb.DatabaseEngine_DATABASE_ENGINE_POSTGRESQL:
		conn.Port = defaultPostgresPort
		if fileExists(postgresSocket) {
			conn.SocketPath = postgresSocket
		}
	}
	return conn
}

func engineLabel(e pb.DatabaseEngine) string {
	switch e {
	case pb.DatabaseEngine_DATABASE_ENGINE_MYSQL:
		return "MySQL"
	case pb.DatabaseEngine_DATABASE_ENGINE_MARIADB:
		return "MariaDB"
	case pb.DatabaseEngine_DATABASE_ENGINE_POSTGRESQL:
		return "PostgreSQL"
	default:
		return "database"
	}
}

func fileExists(path string) bool {
	st, err := os.Stat(path)
	if err != nil {
		return false
	}
	// Accept regular files and sockets — Postgres uses a socket file.
	return !st.IsDir()
}

// bestEffortLocalVersion runs `mysql --version` or `psql --version` to grab
// a version string. Returns "" if the binary is missing or errors out.
func bestEffortLocalVersion(ctx context.Context, engine pb.DatabaseEngine) string {
	var bin string
	switch engine {
	case pb.DatabaseEngine_DATABASE_ENGINE_MYSQL,
		pb.DatabaseEngine_DATABASE_ENGINE_MARIADB:
		bin = "mysql"
	case pb.DatabaseEngine_DATABASE_ENGINE_POSTGRESQL:
		bin = "psql"
	default:
		return ""
	}
	if _, err := exec.LookPath(bin); err != nil {
		return ""
	}
	cctx, cancel := context.WithTimeout(ctx, versionExecTimeout)
	defer cancel()
	out, err := exec.CommandContext(cctx, bin, "--version").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// ---------- docker ----------

var (
	mysqlImageRe    = regexp.MustCompile(`(?i)^(?:[^/]+/)?(?:mysql|mysql-server)(?::|$)`)
	mariadbImageRe  = regexp.MustCompile(`(?i)^(?:[^/]+/)?mariadb(?::|$)`)
	postgresImageRe = regexp.MustCompile(`(?i)^(?:[^/]+/)?(?:postgres|postgresql|postgis)(?::|$)`)
	// Capture the host-side published port from a `docker ps` Ports field
	// such as `0.0.0.0:3307->3306/tcp` or `[::]:5433->5432/tcp`.
	publishedPortRe = regexp.MustCompile(`(?:^|,\s*)(?:[^:,]*:)?(\d+)->(\d+)/tcp`)
)

// dockerAvailable returns true if the docker binary exists and one of the
// expected docker socket paths is readable. Network-mode `docker context`
// setups are out of scope for this PR — we want zero-config local detection.
func dockerAvailable() bool {
	if _, err := exec.LookPath("docker"); err != nil {
		return false
	}
	for _, p := range []string{dockerSockPath, alternateDockerSock} {
		if st, err := os.Stat(p); err == nil && st.Mode()&os.ModeSocket != 0 {
			return true
		}
	}
	return false
}

func scanDocker(ctx context.Context) ([]*pb.DatabaseDiscoveryCandidate, error) {
	if !dockerAvailable() {
		return nil, nil
	}
	cctx, cancel := context.WithTimeout(ctx, dockerPSExecTimeout)
	defer cancel()
	cmd := exec.CommandContext(cctx, "docker", "ps",
		"--no-trunc",
		"--format", "{{.ID}}\t{{.Names}}\t{{.Image}}\t{{.Ports}}")
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	var results []*pb.DatabaseDiscoveryCandidate
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		fields := strings.SplitN(line, "\t", 4)
		if len(fields) < 4 {
			continue
		}
		id, name, image, ports := fields[0], fields[1], fields[2], fields[3]

		engine, ok := matchDockerImageEngine(image)
		if !ok {
			continue
		}

		hostPort, _, ok := parsePublishedPort(ports, defaultPortFor(engine))
		if !ok {
			// No host-side publish — agent can't reach via host TCP. Skip.
			continue
		}

		results = append(results, &pb.DatabaseDiscoveryCandidate{
			Engine:                   engine,
			DiscoveryMethod:          "docker",
			DockerContainerId:        id,
			DockerContainerName:      name,
			DisplayName:              fmt.Sprintf("%s in Docker (%s)", engineLabel(engine), name),
			Connection:               &pb.DatabaseConnection{Host: "127.0.0.1", Port: hostPort},
			Version:                  parseImageVersion(image),
			CredentialsAutoExtracted: false,
			CredentialsSource:        "",
		})
	}
	return results, nil
}

func matchDockerImageEngine(image string) (pb.DatabaseEngine, bool) {
	switch {
	case mysqlImageRe.MatchString(image):
		return pb.DatabaseEngine_DATABASE_ENGINE_MYSQL, true
	case mariadbImageRe.MatchString(image):
		return pb.DatabaseEngine_DATABASE_ENGINE_MARIADB, true
	case postgresImageRe.MatchString(image):
		return pb.DatabaseEngine_DATABASE_ENGINE_POSTGRESQL, true
	}
	return pb.DatabaseEngine_DATABASE_ENGINE_UNSPECIFIED, false
}

func defaultPortFor(engine pb.DatabaseEngine) uint32 {
	switch engine {
	case pb.DatabaseEngine_DATABASE_ENGINE_POSTGRESQL:
		return defaultPostgresPort
	default:
		return defaultMySQLPort
	}
}

// parsePublishedPort returns the host-side and container-side port for the
// first published mapping that targets containerPort. If containerPort is
// zero, the first published TCP mapping wins.
func parsePublishedPort(portsField string, containerPort uint32) (uint32, uint32, bool) {
	matches := publishedPortRe.FindAllStringSubmatch(portsField, -1)
	for _, m := range matches {
		host, err := strconv.ParseUint(m[1], 10, 32)
		if err != nil {
			continue
		}
		ctn, err := strconv.ParseUint(m[2], 10, 32)
		if err != nil {
			continue
		}
		if containerPort != 0 && uint32(ctn) != containerPort {
			continue
		}
		return uint32(host), uint32(ctn), true
	}
	return 0, 0, false
}

// parseImageVersion extracts the tag from `repo:tag` if it looks like a
// version. Returns "" when no tag is present, or the tag is "latest".
func parseImageVersion(image string) string {
	idx := strings.LastIndex(image, ":")
	if idx < 0 {
		return ""
	}
	tag := image[idx+1:]
	if tag == "" || strings.EqualFold(tag, "latest") {
		return ""
	}
	// Strip @sha256... if present after the tag.
	if at := strings.Index(tag, "@"); at >= 0 {
		tag = tag[:at]
	}
	return tag
}

// ---------- port scan ----------

func scanPorts(ctx context.Context, existing []*pb.DatabaseDiscoveryCandidate) []*pb.DatabaseDiscoveryCandidate {
	covered := map[uint32]bool{}
	for _, c := range existing {
		if c.GetConnection() != nil {
			covered[c.GetConnection().GetPort()] = true
		}
	}

	type probe struct {
		port   uint32
		engine pb.DatabaseEngine
	}
	probes := []probe{
		{defaultMySQLPort, pb.DatabaseEngine_DATABASE_ENGINE_MYSQL},
		{defaultPostgresPort, pb.DatabaseEngine_DATABASE_ENGINE_POSTGRESQL},
	}

	var out []*pb.DatabaseDiscoveryCandidate
	for _, p := range probes {
		if covered[p.port] {
			continue
		}
		if err := ctx.Err(); err != nil {
			return out
		}
		if !tcpReachable("127.0.0.1", p.port) {
			continue
		}
		out = append(out, &pb.DatabaseDiscoveryCandidate{
			Engine:          p.engine,
			DiscoveryMethod: "port_scan",
			DisplayName:     fmt.Sprintf("%s on :%d (port_scan)", engineLabel(p.engine), p.port),
			Connection: &pb.DatabaseConnection{
				Host: "127.0.0.1",
				Port: p.port,
			},
		})
	}
	return out
}

func tcpReachable(host string, port uint32) bool {
	addr := net.JoinHostPort(host, strconv.FormatUint(uint64(port), 10))
	conn, err := net.DialTimeout("tcp", addr, portScanTimeout)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}
