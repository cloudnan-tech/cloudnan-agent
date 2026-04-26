// Package database — driver.go.
//
// Engine driver abstraction. Each supported engine (MySQL, MariaDB,
// PostgreSQL) implements Driver to translate a DatabaseConnection plus
// credentials into a *sql.DB ready for use, and to query the server
// version. The handler layer above does not know about DSN syntax or
// engine quirks.
//
// Driver implementations are stateless and safe for concurrent use; each
// Open returns a fresh connection pool tuned for the agent's usage
// pattern (small, short-lived pools — DB ops are issued on demand).
package database

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	mysqldrv "github.com/go-sql-driver/mysql"
	_ "github.com/lib/pq" // postgres driver registration

	pb "github.com/cloudnan-tech/cloudnan-agent/proto/agent"
)

// ErrUnknownEngine is returned by DriverFor for unsupported engines.
var ErrUnknownEngine = errors.New("database: unknown or unsupported engine")

// Driver translates a connection spec into a working *sql.DB and exposes
// engine-specific server-version queries.
type Driver interface {
	Engine() pb.DatabaseEngine
	// Open returns a *sql.DB ready to use. The caller is responsible for
	// Close(). Open performs a PingContext before returning.
	Open(ctx context.Context, conn *pb.DatabaseConnection, username, password string) (*sql.DB, error)
	// Version queries the connected server for its version string.
	Version(ctx context.Context, db *sql.DB) (string, error)
}

// DriverFor returns the driver implementation for engine. Returns
// ErrUnknownEngine for engines this PR does not support.
func DriverFor(engine pb.DatabaseEngine) (Driver, error) {
	switch engine {
	case pb.DatabaseEngine_DATABASE_ENGINE_MYSQL,
		pb.DatabaseEngine_DATABASE_ENGINE_MARIADB:
		return &mysqlDriver{engine: engine}, nil
	case pb.DatabaseEngine_DATABASE_ENGINE_POSTGRESQL:
		return &postgresDriver{}, nil
	default:
		return nil, fmt.Errorf("%w: %v", ErrUnknownEngine, engine)
	}
}

// applyPoolDefaults sets the small, short-lived pool we want for agent use.
func applyPoolDefaults(db *sql.DB) {
	db.SetMaxOpenConns(2)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(5 * time.Minute)
}

// ---------- MySQL / MariaDB ----------

type mysqlDriver struct {
	engine pb.DatabaseEngine
}

func (d *mysqlDriver) Engine() pb.DatabaseEngine { return d.engine }

// mysqlTLSRegistry serializes mysql.RegisterTLSConfig calls — the underlying
// map in the driver is not safe for concurrent registration.
var mysqlTLSRegistry sync.Mutex

func (d *mysqlDriver) Open(ctx context.Context, conn *pb.DatabaseConnection, username, password string) (*sql.DB, error) {
	if conn == nil {
		return nil, errors.New("mysql: nil connection")
	}
	cfg := mysqldrv.NewConfig()
	cfg.User = username
	cfg.Passwd = password
	cfg.ParseTime = true
	cfg.Timeout = 10 * time.Second
	cfg.ReadTimeout = 30 * time.Second
	cfg.WriteTimeout = 30 * time.Second

	switch {
	case conn.GetPort() == 0 && conn.GetSocketPath() != "":
		cfg.Net = "unix"
		cfg.Addr = conn.GetSocketPath()
	default:
		cfg.Net = "tcp"
		host := conn.GetHost()
		if host == "" {
			host = "127.0.0.1"
		}
		port := conn.GetPort()
		if port == 0 {
			port = defaultMySQLPort
		}
		cfg.Addr = net.JoinHostPort(host, strconv.FormatUint(uint64(port), 10))
	}

	if conn.GetUseTls() {
		tlsName, err := registerMySQLTLS(conn)
		if err != nil {
			return nil, fmt.Errorf("mysql: register TLS: %w", err)
		}
		cfg.TLSConfig = tlsName
	}

	dsn := cfg.FormatDSN()
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, fmt.Errorf("mysql: open: %w", err)
	}
	applyPoolDefaults(db)
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("mysql: ping: %w", err)
	}
	return db, nil
}

func (d *mysqlDriver) Version(ctx context.Context, db *sql.DB) (string, error) {
	var ver string
	if err := db.QueryRowContext(ctx, "SELECT VERSION()").Scan(&ver); err != nil {
		return "", fmt.Errorf("mysql: version query: %w", err)
	}
	return ver, nil
}

// registerMySQLTLS installs a TLS config keyed by a fingerprint of the CA
// PEM (or "system" when no CA is provided) and returns the name used in the
// DSN. Repeated calls with identical inputs are idempotent.
func registerMySQLTLS(conn *pb.DatabaseConnection) (string, error) {
	mysqlTLSRegistry.Lock()
	defer mysqlTLSRegistry.Unlock()

	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: conn.GetHost()}
	caPEM := conn.GetTlsCaPem()
	var name string
	if caPEM == "" {
		name = "cloudnan-system"
	} else {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM([]byte(caPEM)) {
			return "", errors.New("invalid CA PEM")
		}
		tlsCfg.RootCAs = pool
		sum := sha256.Sum256([]byte(caPEM))
		name = "cloudnan-" + hex.EncodeToString(sum[:8])
	}
	// The driver returns an error on duplicate-name registration. Deregister
	// any prior config under this name so repeated Open calls converge on
	// the latest CA pool — important when an operator rotates the CA bundle.
	mysqldrv.DeregisterTLSConfig(name)
	if err := mysqldrv.RegisterTLSConfig(name, tlsCfg); err != nil {
		return "", err
	}
	return name, nil
}

// ---------- PostgreSQL ----------

type postgresDriver struct{}

func (d *postgresDriver) Engine() pb.DatabaseEngine {
	return pb.DatabaseEngine_DATABASE_ENGINE_POSTGRESQL
}

func (d *postgresDriver) Open(ctx context.Context, conn *pb.DatabaseConnection, username, password string) (*sql.DB, error) {
	if conn == nil {
		return nil, errors.New("postgres: nil connection")
	}
	host := conn.GetHost()
	if host == "" {
		host = "127.0.0.1"
	}
	port := conn.GetPort()
	if port == 0 && conn.GetSocketPath() == "" {
		port = defaultPostgresPort
	}

	u := &url.URL{
		Scheme: "postgres",
		User:   url.UserPassword(username, password),
		Path:   "/postgres",
	}
	if conn.GetPort() == 0 && conn.GetSocketPath() != "" {
		// pq supports unix sockets via host=/path/dir; the socket file's
		// directory is what postgres expects. Strip the `.s.PGSQL.NNNN`
		// suffix to get the directory.
		u.Host = ""
		dir := filepath.Dir(conn.GetSocketPath())
		q := u.Query()
		q.Set("host", dir)
		u.RawQuery = q.Encode()
	} else {
		u.Host = net.JoinHostPort(host, strconv.FormatUint(uint64(port), 10))
	}

	q := u.Query()
	q.Set("connect_timeout", "10")
	if conn.GetUseTls() {
		q.Set("sslmode", "verify-full")
		if pem := conn.GetTlsCaPem(); pem != "" {
			// pq reads sslrootcert on every new physical connection, so the
			// CA file must outlive every Open() call. writeTempCA uses a
			// content-addressed name so identical CAs deduplicate; the OS
			// reclaims the file when the agent exits.
			caPath, err := writeTempCA(pem)
			if err != nil {
				return nil, fmt.Errorf("postgres: write CA: %w", err)
			}
			q.Set("sslrootcert", caPath)
		}
	} else {
		q.Set("sslmode", "disable")
	}
	u.RawQuery = q.Encode()

	db, err := sql.Open("postgres", u.String())
	if err != nil {
		return nil, fmt.Errorf("postgres: open: %w", err)
	}
	applyPoolDefaults(db)
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("postgres: ping: %w", err)
	}
	return db, nil
}

func (d *postgresDriver) Version(ctx context.Context, db *sql.DB) (string, error) {
	var ver string
	if err := db.QueryRowContext(ctx, "SHOW server_version").Scan(&ver); err != nil {
		return "", fmt.Errorf("postgres: version query: %w", err)
	}
	return ver, nil
}

// writeTempCA writes pem to a deterministic file under the OS temp dir so
// repeated calls for the same CA reuse the same file. The file is created
// with mode 0600 and lives for the process lifetime.
func writeTempCA(pem string) (string, error) {
	sum := sha256.Sum256([]byte(pem))
	name := "cloudnan-pgca-" + hex.EncodeToString(sum[:8]) + ".pem"
	path := filepath.Join(os.TempDir(), name)

	if st, err := os.Stat(path); err == nil && st.Size() == int64(len(pem)) {
		return path, nil
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return "", err
	}
	if _, err := f.WriteString(pem); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return "", err
	}
	if err := f.Close(); err != nil {
		return "", err
	}
	return path, nil
}
