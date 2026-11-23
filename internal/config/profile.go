package config

import (
	"errors"
	"fmt"
	"net/mail"
	"net/netip"
	"regexp"
	"strings"

	"github.com/mreza-mz/serverforge/internal/vault"
)

const Version = 1

type Module string

const (
	Docker        Module = "docker"
	DockerCompose Module = "docker_compose"
	Nginx         Module = "nginx"
	Caddy         Module = "caddy"
	PostgreSQL    Module = "postgresql"
	MySQL         Module = "mysql"
	MariaDB       Module = "mariadb"
	Redis         Module = "redis"
	SSL           Module = "ssl"
)

const (
	Local = "local"
	SSH   = "ssh"
)

type ModuleOption struct {
	Module Module
	Label  string
}

func Modules() []ModuleOption {
	return []ModuleOption{
		{Docker, "Docker"}, {DockerCompose, "Docker Compose"},
		{Nginx, "Nginx"}, {Caddy, "Caddy"},
		{PostgreSQL, "PostgreSQL"}, {MySQL, "MySQL"}, {MariaDB, "MariaDB"},
		{Redis, "Redis"}, {SSL, "SSL / TLS"},
	}
}

type DatabaseModule struct {
	Module      Module
	Label       string
	DefaultPort int
	maxName     int
	maxUser     int
}

func DatabaseModules() []DatabaseModule {
	return []DatabaseModule{
		{PostgreSQL, "PostgreSQL", 5432, 63, 63},
		{MySQL, "MySQL", 3306, 64, 32},
		{MariaDB, "MariaDB", 3306, 64, 80},
	}
}

func (m Module) PasswordKey() string { return string(m) + "_password" }

type Profile struct {
	Version   int                 `yaml:"version"`
	Target    Target              `yaml:"target"`
	Modules   []Module            `yaml:"modules,omitempty"`
	Databases map[Module]Database `yaml:"databases,omitempty"`
	Web       *Web                `yaml:"web,omitempty"`
	Redis     *RedisSettings      `yaml:"redis,omitempty"`
	TLS       *TLS                `yaml:"tls,omitempty"`
	Security  Security            `yaml:"security,omitempty"`
	Vault     string              `yaml:"vault,omitempty"`
}

type Target struct {
	Connection string `yaml:"connection" json:"connection"`
	Host       string `yaml:"host,omitempty" json:"host,omitempty"`
	User       string `yaml:"user,omitempty" json:"user,omitempty"`
	Port       int    `yaml:"port,omitempty" json:"port,omitempty"`
}

type Database struct {
	Name string `yaml:"name"`
	User string `yaml:"user"`
	Port int    `yaml:"port"`
}

type Web struct {
	Domain   string `yaml:"domain"`
	HTTPPort int    `yaml:"http_port"`
}

type RedisSettings struct {
	Port int `yaml:"port"`
}

type TLS struct {
	Email string `yaml:"email"`
	Port  int    `yaml:"port"`
}

// Security records choices for the profile. A future apply must request its own approvals.
type Security struct {
	UFW             bool `yaml:"ufw,omitempty"`
	Fail2ban        bool `yaml:"fail2ban,omitempty"`
	SecurityUpdates bool `yaml:"security_updates,omitempty"`
}

func (p Profile) Validate() error {
	if p.Version != Version {
		return errors.New("version must be 1")
	}
	if err := p.Target.validate(); err != nil {
		return err
	}
	selected, err := SelectModules(p.Modules)
	if err != nil {
		return err
	}
	webSelected := selected[Nginx] || selected[Caddy]
	if (p.Web != nil) != webSelected {
		return errors.New("web settings must be present exactly when nginx or caddy is selected")
	}
	if (p.TLS != nil) != selected[SSL] {
		return errors.New("tls settings must be present exactly when ssl is selected")
	}
	if (p.Redis != nil) != selected[Redis] {
		return errors.New("redis settings must be present exactly when redis is selected")
	}

	ports := make(map[int]string)
	if p.Target.Connection == SSH {
		ports[p.Target.Port] = "target.port"
	}
	if err := p.validateDatabases(selected, ports); err != nil {
		return err
	}
	if p.Web != nil {
		if err := ValidateDomain(p.Web.Domain); err != nil {
			return fmt.Errorf("web.domain: %w", err)
		}
		if err := reservePort(ports, "web.http_port", p.Web.HTTPPort); err != nil {
			return err
		}
	}
	if p.TLS != nil {
		if err := ValidateEmail(p.TLS.Email); err != nil {
			return fmt.Errorf("tls.email: %w", err)
		}
		if err := reservePort(ports, "tls.port", p.TLS.Port); err != nil {
			return err
		}
	}
	if p.Redis != nil {
		if err := reservePort(ports, "redis.port", p.Redis.Port); err != nil {
			return err
		}
	}
	needsVault := len(p.Databases) > 0 || selected[Redis]
	if needsVault && p.Vault == "" {
		return errors.New("vault is required for database and Redis credentials")
	}
	if !needsVault && p.Vault != "" {
		return errors.New("vault requires a database or Redis module")
	}
	if needsVault {
		return vault.Validate(p.Vault)
	}
	return nil
}

// SelectModules validates module combinations and returns the selected set.
func SelectModules(modules []Module) (map[Module]bool, error) {
	selected := make(map[Module]bool)
	allowed := make(map[Module]bool)
	for _, option := range Modules() {
		allowed[option.Module] = true
	}
	for _, module := range modules {
		if !allowed[module] {
			return nil, errors.New("modules contains an unknown name")
		}
		if selected[module] {
			return nil, fmt.Errorf("modules contains duplicate %s", module)
		}
		selected[module] = true
	}
	if selected[DockerCompose] && !selected[Docker] {
		return nil, errors.New("docker_compose requires docker")
	}
	if selected[Nginx] && selected[Caddy] {
		return nil, errors.New("select at most one of nginx and caddy")
	}
	if selected[MySQL] && selected[MariaDB] {
		return nil, errors.New("select at most one of mysql and mariadb")
	}
	if selected[SSL] && !selected[Nginx] && !selected[Caddy] {
		return nil, errors.New("ssl requires nginx or caddy")
	}
	return selected, nil
}

func (p Profile) validateDatabases(selected map[Module]bool, ports map[int]string) error {
	matched := 0
	for _, option := range DatabaseModules() {
		database, present := p.Databases[option.Module]
		if present != selected[option.Module] {
			return fmt.Errorf("databases.%s must be present exactly when %s is selected", option.Module, option.Module)
		}
		if !present {
			continue
		}
		matched++
		if err := option.ValidateName(database.Name); err != nil {
			return fmt.Errorf("databases.%s.name: %w", option.Module, err)
		}
		if err := option.ValidateUser(database.User); err != nil {
			return fmt.Errorf("databases.%s.user: %w", option.Module, err)
		}
		if err := reservePort(ports, "databases."+string(option.Module)+".port", database.Port); err != nil {
			return err
		}
	}
	if matched != len(p.Databases) {
		return errors.New("databases contains an unknown engine")
	}
	return nil
}

func (t Target) validate() error {
	switch t.Connection {
	case Local:
		if t.Host != "" || t.User != "" || t.Port != 0 {
			return errors.New("local targets must omit host, user and port")
		}
	case SSH:
		if err := ValidateHost(t.Host); err != nil {
			return fmt.Errorf("target.host: %w", err)
		}
		if err := ValidateSSHUser(t.User); err != nil {
			return fmt.Errorf("target.user: %w", err)
		}
		if err := ValidatePort(t.Port); err != nil {
			return fmt.Errorf("target.port: %w", err)
		}
	default:
		return errors.New("target.connection must be local or ssh")
	}
	return nil
}

var (
	dnsLabel = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)
	dbIdent  = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)
	sshUser  = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_-]{0,31}$`)
)

func isHostname(value string) bool {
	if len(value) > 253 {
		return false
	}
	for label := range strings.SplitSeq(value, ".") {
		if !dnsLabel.MatchString(label) {
			return false
		}
	}
	return true
}

func ValidateHost(value string) error {
	ip, err := netip.ParseAddr(value)
	if !isHostname(value) && (err != nil || ip.Zone() != "") {
		return errors.New("enter a hostname or an unbracketed IP address")
	}
	return nil
}

func ValidateSSHUser(value string) error {
	if !sshUser.MatchString(value) {
		return errors.New("enter an SSH username of up to 32 letters, digits, underscores or hyphens beginning with a letter or underscore")
	}
	return nil
}

func ValidateDomain(value string) error {
	_, ipErr := netip.ParseAddr(value)
	if ipErr == nil || !isHostname(value) || !strings.Contains(value, ".") {
		return errors.New("enter a fully qualified domain name")
	}
	return nil
}

func ValidateEmail(value string) error {
	address, err := mail.ParseAddress(value)
	if err != nil || address.Address != value {
		return errors.New("enter an email address")
	}
	_, domain, _ := strings.Cut(value, "@")
	if ValidateDomain(domain) != nil {
		return errors.New("enter an email address with a fully qualified domain")
	}
	return nil
}

func (d DatabaseModule) ValidateName(value string) error { return validateIdentifier(value, d.maxName) }
func (d DatabaseModule) ValidateUser(value string) error { return validateIdentifier(value, d.maxUser) }

func validateIdentifier(value string, limit int) error {
	if len(value) > limit || !dbIdent.MatchString(value) {
		return fmt.Errorf("enter up to %d letters, digits or underscores beginning with a letter or underscore", limit)
	}
	return nil
}

func ValidatePort(port int) error {
	if port < 1 || port > 65535 {
		return errors.New("enter a port between 1 and 65535")
	}
	return nil
}

func reservePort(ports map[int]string, field string, port int) error {
	if err := ValidatePort(port); err != nil {
		return fmt.Errorf("%s: %w", field, err)
	}
	if other, found := ports[port]; found {
		return fmt.Errorf("%s conflicts with %s", field, other)
	}
	ports[port] = field
	return nil
}
