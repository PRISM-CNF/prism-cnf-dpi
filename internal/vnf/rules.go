package vnf

import (
	"context"
	"fmt"

	"github.com/networkservicemesh/sdk/pkg/tools/log"
	"nse-ovs-dpi/internal/processor"
)

func DefaultRuleInstaller(options Options) RuleInstaller {
	options = options.withDefaults()
	return RuleInstallerFunc(func(ctx context.Context, sessionCtx *SessionContext) (processor.Session, error) {
		return installTrafficRules(ctx, sessionCtx, options)
	})
}

// installTrafficRules persists the current Suricata rule snapshot in session state.
// DPI v1 does not install kernel data-plane rules because inspection stays alert-only.
func installTrafficRules(ctx context.Context, sessionCtx *SessionContext, options Options) (processor.Session, error) {
	if sessionCtx == nil {
		return nil, fmt.Errorf("session context is required")
	}
	if err := options.validate(); err != nil {
		return nil, err
	}

	snapshot, err := loadRuleSnapshot(options.RulesPath)
	if err != nil {
		return nil, fmt.Errorf("load dpi rules from %s: %w", options.RulesPath, err)
	}

	if state := sessionCtx.State(); state != nil {
		state.Store(StateKeyDPIRulesPath, options.RulesPath)
		state.Store(StateKeyDPIRuleHash, snapshot.Hash)
		state.Store(StateKeyDPIRuleCount, snapshot.RuleCount)
		state.Store(StateKeyDPISuricataConfig, options.SuricataConfigPath)
		state.Store(StateKeyDPIHTTPPort, options.HTTPPort)
	}

	log.FromContext(ctx).Infof(
		"loaded dpi rules path=%s count=%d hash=%s http_port=%d",
		options.RulesPath,
		snapshot.RuleCount,
		shortHash(snapshot.Hash),
		options.HTTPPort,
	)

	return processor.CloseFunc(func(context.Context) error {
		return nil
	}), nil
}
