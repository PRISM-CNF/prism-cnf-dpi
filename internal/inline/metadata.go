package inline

import (
	"context"

	"github.com/networkservicemesh/api/pkg/api/networkservice"
	nsmetadata "github.com/networkservicemesh/sdk/pkg/networkservice/utils/metadata"

	"nse-ovs-dpi/internal/processor"
)

type originalConnectionKey struct{}
type downstreamConnectionKey struct{}
type processorSessionKey struct{}

type processorSessionState struct {
	flow    *processor.Flow
	session processor.Session
}

func storeOriginalConnection(ctx context.Context, conn *networkservice.Connection) {
	if conn == nil {
		return
	}
	nsmetadata.Map(ctx, false).Store(originalConnectionKey{}, conn.Clone())
}

func loadOriginalConnection(ctx context.Context) *networkservice.Connection {
	rawValue, ok := nsmetadata.Map(ctx, false).Load(originalConnectionKey{})
	if !ok {
		return nil
	}
	conn, ok := rawValue.(*networkservice.Connection)
	if !ok || conn == nil {
		return nil
	}
	return conn.Clone()
}

func deleteOriginalConnection(ctx context.Context) {
	_, _ = nsmetadata.Map(ctx, false).LoadAndDelete(originalConnectionKey{})
}

func storeDownstreamConnection(ctx context.Context, conn *networkservice.Connection) {
	if conn == nil {
		return
	}
	nsmetadata.Map(ctx, false).Store(downstreamConnectionKey{}, conn.Clone())
}

func loadDownstreamConnection(ctx context.Context) (*networkservice.Connection, bool) {
	rawValue, ok := nsmetadata.Map(ctx, false).Load(downstreamConnectionKey{})
	if !ok {
		return nil, false
	}
	conn, ok := rawValue.(*networkservice.Connection)
	if !ok || conn == nil {
		return nil, false
	}
	return conn.Clone(), true
}

func loadAndDeleteDownstreamConnection(ctx context.Context) (*networkservice.Connection, bool) {
	rawValue, ok := nsmetadata.Map(ctx, false).LoadAndDelete(downstreamConnectionKey{})
	if !ok {
		return nil, false
	}
	conn, ok := rawValue.(*networkservice.Connection)
	if !ok || conn == nil {
		return nil, false
	}
	return conn.Clone(), true
}

func storeProcessorSession(ctx context.Context, flow *processor.Flow, session processor.Session) {
	if flow == nil || session == nil {
		return
	}
	nsmetadata.Map(ctx, false).Store(processorSessionKey{}, &processorSessionState{
		flow:    flow.Clone(),
		session: session,
	})
}

func loadProcessorSession(ctx context.Context) (processor.Session, *processor.Flow, bool) {
	rawValue, ok := nsmetadata.Map(ctx, false).Load(processorSessionKey{})
	if !ok {
		return nil, nil, false
	}
	state, ok := rawValue.(*processorSessionState)
	if !ok || state == nil || state.session == nil {
		return nil, nil, false
	}
	return state.session, state.flow.Clone(), true
}

func loadAndDeleteProcessorSession(ctx context.Context) (processor.Session, *processor.Flow, bool) {
	rawValue, ok := nsmetadata.Map(ctx, false).LoadAndDelete(processorSessionKey{})
	if !ok {
		return nil, nil, false
	}
	state, ok := rawValue.(*processorSessionState)
	if !ok || state == nil || state.session == nil {
		return nil, nil, false
	}
	return state.session, state.flow.Clone(), true
}

func closeProcessorSession(ctx context.Context) error {
	session, _, ok := loadAndDeleteProcessorSession(ctx)
	if !ok {
		return nil
	}
	return session.Close(ctx)
}

func reuseProcessorSession(ctx context.Context, flow *processor.Flow) (bool, error) {
	_, existingFlow, ok := loadProcessorSession(ctx)
	if !ok {
		return false, nil
	}
	if sameProcessorFlow(existingFlow, flow) {
		return true, nil
	}
	return false, closeProcessorSession(ctx)
}

func sameProcessorFlow(a *processor.Flow, b *processor.Flow) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.ConnectionID == b.ConnectionID &&
		a.IngressInterface == b.IngressInterface &&
		a.EgressInterface == b.EgressInterface
}
