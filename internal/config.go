//go:build linux
// +build linux

package internal

import (
	"context"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/kelseyhightower/envconfig"
	"github.com/pkg/errors"
)

type Config struct {
	Name                   string            `default:"nse-ovs-dpi" desc:"Name of inline DPI NSE"`
	ListenOn               string            `default:"listen.on.sock" desc:"listen on socket" split_words:"true"`
	ConnectTo              url.URL           `default:"unix:///var/lib/networkservicemesh/nsm.io.sock" desc:"url to connect to" split_words:"true"`
	MaxTokenLifetime       time.Duration     `default:"10m" desc:"maximum lifetime of tokens" split_words:"true"`
	RegistryClientPolicies []string          `default:"" desc:"paths to files and directories that contain registry client policies" split_words:"true"`
	ServiceName            string            `default:"nse-ovs-dpi" desc:"name of provided network service" split_words:"true"`
	Labels                 map[string]string `default:"app:dpi" desc:"endpoint labels"`
	DownstreamLabels       map[string]string `default:"" desc:"labels used to select downstream endpoints; empty preserves the incoming request labels" split_words:"true"`
	DPIRulesPath           string            `default:"/etc/nse-dpi/local.rules" desc:"path to the Suricata rules file" split_words:"true"`
	DPISuricataConfigPath  string            `default:"/etc/suricata/suricata.yaml" desc:"path to the Suricata base config file" split_words:"true"`
	DPITempRoot            string            `default:"/tmp/nse-ovs-dpi" desc:"session temp root for Suricata logs and eve.json" split_words:"true"`
	DPIRulePollInterval    time.Duration     `default:"2s" desc:"interval for polling the DPI rules file for live reload" split_words:"true"`
	DPIHTTPPort            int               `default:"8080" desc:"documented HTTP service port for DPI v1 rules" split_words:"true"`
	LogLevel               string            `default:"INFO" desc:"log level" split_words:"true"`
	OpenTelemetryEndpoint  string            `default:"otel-collector.observability.svc.cluster.local:4317" desc:"OpenTelemetry Collector Endpoint" split_words:"true"`
	MetricsExportInterval  time.Duration     `default:"10s" desc:"interval between metrics exports" split_words:"true"`
	PprofEnabled           bool              `default:"false" desc:"is pprof enabled" split_words:"true"`
	PprofListenOn          string            `default:"localhost:6060" desc:"pprof URL to ListenAndServe" split_words:"true"`
}

func LoadConfig(_ context.Context) (*Config, error) {
	config := new(Config)

	if err := envconfig.Usage("nsm", config); err != nil {
		return nil, errors.Wrap(err, "cannot show usage of envconfig nsm")
	}

	if err := envconfig.Process("nsm", config); err != nil {
		return nil, errors.Wrap(err, "cannot process envconfig nsm")
	}

	if config.ServiceName == "" {
		config.ServiceName = config.Name
	}

	if config.Labels == nil {
		config.Labels = map[string]string{}
	}

	if len(config.DownstreamLabels) == 0 && len(config.Labels) > 0 {
		config.DownstreamLabels = make(map[string]string, len(config.Labels))
		for key, value := range config.Labels {
			config.DownstreamLabels[key] = value
		}
	}

	if err := requireReadableFile(config.DPIRulesPath); err != nil {
		return nil, errors.Wrapf(err, "cannot load dpi rules from %s", config.DPIRulesPath)
	}
	if err := requireReadableFile(config.DPISuricataConfigPath); err != nil {
		return nil, errors.Wrapf(err, "cannot load suricata config from %s", config.DPISuricataConfigPath)
	}
	if config.DPIRulePollInterval <= 0 {
		return nil, errors.New("dpi rule poll interval must be positive")
	}
	if config.DPIHTTPPort <= 0 || config.DPIHTTPPort > 65535 {
		return nil, errors.New("dpi http port must be between 1 and 65535")
	}
	if strings.TrimSpace(config.DPITempRoot) == "" {
		return nil, errors.New("dpi temp root must not be empty")
	}

	return config, nil
}

func requireReadableFile(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if info.IsDir() {
		return errors.Errorf("%s is a directory", path)
	}
	return nil
}
