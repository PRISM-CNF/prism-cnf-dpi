package inline

import (
	"context"
	"testing"

	"github.com/networkservicemesh/api/pkg/api/networkservice"
	"github.com/networkservicemesh/sdk/pkg/networkservice/core/chain"
	nsmetadata "github.com/networkservicemesh/sdk/pkg/networkservice/utils/metadata"
	"google.golang.org/protobuf/types/known/emptypb"

	"nse-ovs-dpi/internal/processor"
)

type countingSession struct {
	closeCalls int
}

func (s *countingSession) Close(context.Context) error {
	s.closeCalls++
	return nil
}

type testNetworkServiceServer struct {
	request func(context.Context, *networkservice.NetworkServiceRequest) (*networkservice.Connection, error)
	close   func(context.Context, *networkservice.Connection) (*emptypb.Empty, error)
}

func (s *testNetworkServiceServer) Request(ctx context.Context, request *networkservice.NetworkServiceRequest) (*networkservice.Connection, error) {
	if s.request != nil {
		return s.request(ctx, request)
	}
	return request.GetConnection().Clone(), nil
}

func (s *testNetworkServiceServer) Close(ctx context.Context, conn *networkservice.Connection) (*emptypb.Empty, error) {
	if s.close != nil {
		return s.close(ctx, conn)
	}
	return &emptypb.Empty{}, nil
}

func TestReuseProcessorSessionSameFlowKeepsActiveSession(t *testing.T) {
	flow := &processor.Flow{
		ConnectionID:     "test-conn",
		IngressInterface: "nse-ovs-dp-a",
		EgressInterface:  "nse-ovs-dp-b",
	}
	session := &countingSession{}

	server := chain.NewNetworkServiceServer(
		nsmetadata.NewServer(),
		&testNetworkServiceServer{
			request: func(ctx context.Context, request *networkservice.NetworkServiceRequest) (*networkservice.Connection, error) {
				storeProcessorSession(ctx, flow, session)

				reused, err := reuseProcessorSession(ctx, flow.Clone())
				if err != nil {
					t.Fatalf("reuse processor session: %v", err)
				}
				if !reused {
					t.Fatalf("expected same flow to reuse active processor session")
				}
				if session.closeCalls != 0 {
					t.Fatalf("same-flow reuse unexpectedly closed session: %d", session.closeCalls)
				}

				_, storedFlow, ok := loadProcessorSession(ctx)
				if !ok {
					t.Fatalf("expected stored processor session")
				}
				if !sameProcessorFlow(storedFlow, flow) {
					t.Fatalf("stored flow = %#v, want %#v", storedFlow, flow)
				}

				return request.GetConnection().Clone(), nil
			},
		},
	)

	request := &networkservice.NetworkServiceRequest{
		Connection: &networkservice.Connection{Id: flow.ConnectionID},
	}
	if _, err := server.Request(context.Background(), request); err != nil {
		t.Fatalf("request failed: %v", err)
	}
}

func TestReuseProcessorSessionDifferentFlowClosesStaleSession(t *testing.T) {
	currentFlow := &processor.Flow{
		ConnectionID:     "test-conn",
		IngressInterface: "nse-ovs-dp-a",
		EgressInterface:  "nse-ovs-dp-b",
	}
	nextFlow := &processor.Flow{
		ConnectionID:     "test-conn",
		IngressInterface: "nse-ovs-dp-c",
		EgressInterface:  "nse-ovs-dp-b",
	}
	session := &countingSession{}

	server := chain.NewNetworkServiceServer(
		nsmetadata.NewServer(),
		&testNetworkServiceServer{
			request: func(ctx context.Context, request *networkservice.NetworkServiceRequest) (*networkservice.Connection, error) {
				storeProcessorSession(ctx, currentFlow, session)

				reused, err := reuseProcessorSession(ctx, nextFlow)
				if err != nil {
					t.Fatalf("recycle processor session: %v", err)
				}
				if reused {
					t.Fatalf("expected different flow to force processor session recycle")
				}
				if session.closeCalls != 1 {
					t.Fatalf("stale session close count = %d, want 1", session.closeCalls)
				}

				if _, _, ok := loadProcessorSession(ctx); ok {
					t.Fatalf("expected stale processor session metadata to be cleared")
				}

				return request.GetConnection().Clone(), nil
			},
		},
	)

	request := &networkservice.NetworkServiceRequest{
		Connection: &networkservice.Connection{Id: currentFlow.ConnectionID},
	}
	if _, err := server.Request(context.Background(), request); err != nil {
		t.Fatalf("request failed: %v", err)
	}
}
