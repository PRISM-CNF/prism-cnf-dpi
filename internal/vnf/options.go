package vnf

import (
	"fmt"
	"strings"
	"time"
)

const (
	defaultRulesPath        = "/etc/nse-dpi/local.rules"
	defaultSuricataConfig   = "/etc/suricata/suricata.yaml"
	defaultTempRoot         = "/tmp/nse-ovs-dpi"
	defaultRulePollInterval = 2 * time.Second
	defaultHTTPPort         = 8080
	defaultSuricataBinary   = "suricata"
)

type Options struct {
	RulesPath          string
	SuricataConfigPath string
	TempRoot           string
	RulePollInterval   time.Duration
	HTTPPort           int
	SuricataBinary     string
}

func (o Options) withDefaults() Options {
	if strings.TrimSpace(o.RulesPath) == "" {
		o.RulesPath = defaultRulesPath
	}
	if strings.TrimSpace(o.SuricataConfigPath) == "" {
		o.SuricataConfigPath = defaultSuricataConfig
	}
	if strings.TrimSpace(o.TempRoot) == "" {
		o.TempRoot = defaultTempRoot
	}
	if o.RulePollInterval <= 0 {
		o.RulePollInterval = defaultRulePollInterval
	}
	if o.HTTPPort == 0 {
		o.HTTPPort = defaultHTTPPort
	}
	if strings.TrimSpace(o.SuricataBinary) == "" {
		o.SuricataBinary = defaultSuricataBinary
	}
	return o
}

func (o Options) validate() error {
	if strings.TrimSpace(o.RulesPath) == "" {
		return fmt.Errorf("dpi rules path is required")
	}
	if strings.TrimSpace(o.SuricataConfigPath) == "" {
		return fmt.Errorf("suricata config path is required")
	}
	if strings.TrimSpace(o.TempRoot) == "" {
		return fmt.Errorf("dpi temp root is required")
	}
	if o.RulePollInterval <= 0 {
		return fmt.Errorf("dpi rule poll interval must be positive")
	}
	if o.HTTPPort <= 0 || o.HTTPPort > 65535 {
		return fmt.Errorf("dpi http port must be between 1 and 65535")
	}
	if strings.TrimSpace(o.SuricataBinary) == "" {
		return fmt.Errorf("suricata binary is required")
	}
	return nil
}
