package vnf

import (
	"context"

	"nse-ovs-dpi/internal/processor"
)

func NewNoopRuntimeHook() RuntimeHook {
	return RuntimeHookFunc(func(_ context.Context, _ *SessionContext) (processor.Session, error) {
		return processor.CloseFunc(func(context.Context) error {
			return nil
		}), nil
	})
}

// startTrafficProcessing is the second customization point for VNFs that need
// long-lived user-space logic. DPI v1 overrides it with a Suricata subprocess.
func startNoopTrafficProcessing(_ context.Context, _ *SessionContext) (processor.Session, error) {
	return processor.CloseFunc(func(context.Context) error {
		return nil
	}), nil
}
