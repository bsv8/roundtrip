package core_test

import (
	"context"
	"testing"
	"time"

	"github.com/bsv8/roundtrip/go/core"
)

// The call deadline has to bound the wait on its own.
//
// A transport is allowed to be slow, and it is allowed to be written badly. If
// the deadline only worked when the adapter cooperated, then an exchange that
// ignores cancellation would both hang the caller and be able to hand a late
// answer back as if the call had succeeded in time.

const deadlineDelay = 20 * time.Millisecond

func deadlineClient(t *testing.T, timeout time.Duration) *core.Core {
	t.Helper()
	built, err := core.New(core.Config{
		Signer:      testSigner(t, "alice"),
		Now:         func() int64 { return testNow },
		CallTimeout: timeout,
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	return built
}

// responderFor produces genuine signed responses for whatever it is handed.
func responderFor(t *testing.T) (respond func([]byte) ([]byte, error), calls func() int) {
	t.Helper()
	count := 0
	service := newReceiver(t, "bob")
	return func(requestBytes []byte) ([]byte, error) {
		count++
		processed, err := service.core.Handle(context.Background(), requestBytes, core.HandleOptions{})
		if err != nil {
			return nil, err
		}
		return processed.Bytes, nil
	}, func() int { return count }
}

func TestCallDeadlineRefusesALateValidResponse(t *testing.T) {
	respond, calls := responderFor(t)
	// The transport ignores the context and answers late, with a perfectly valid
	// signed response. The caller stopped waiting, so this is not its result.
	late := func(ctx context.Context, requestBytes []byte) ([]byte, error) {
		time.Sleep(deadlineDelay * 6)
		return respond(requestBytes)
	}
	caller := deadlineClient(t, deadlineDelay)
	prepared, err := caller.BuildRequest(context.Background(), testPublicKey(t, "bob"), mustObject(t, `{"op":"ping"}`), core.BuildRequestOptions{})
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	outcome, err := caller.Send(context.Background(), prepared, late)
	if err == nil {
		t.Fatalf("a late answer completed the call: %+v", outcome)
	}
	if code := core.CodeOf(err); code != core.ErrCallTimeout {
		t.Errorf("got %q, want ERR_CALL_TIMEOUT", code)
	}
	// The business did run on the far side. The point is that this call does not
	// report its result as a success it obtained in time.
	deadline := time.Now().Add(5 * time.Second)
	for calls() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if calls() != 1 {
		t.Errorf("the far side ran %d times, want 1", calls())
	}
}

func TestCallDeadlineEndsTheWaitWithoutAdapterCooperation(t *testing.T) {
	// The worst case: an exchange that ignores cancellation and never returns.
	// Nothing about the deadline may depend on the adapter cooperating.
	respond, calls := responderFor(t)
	stubborn := func(ctx context.Context, requestBytes []byte) ([]byte, error) {
		select {
		case <-time.After(10 * time.Second):
			return respond(requestBytes)
		}
	}
	caller := deadlineClient(t, deadlineDelay)
	prepared, err := caller.BuildRequest(context.Background(), testPublicKey(t, "bob"), mustObject(t, `{"op":"ping"}`), core.BuildRequestOptions{})
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	started := time.Now()
	_, err = caller.Send(context.Background(), prepared, stubborn)
	elapsed := time.Since(started)
	if code := core.CodeOf(err); code != core.ErrCallTimeout {
		t.Errorf("got %q, want ERR_CALL_TIMEOUT", code)
	}
	if elapsed < deadlineDelay-time.Millisecond {
		t.Errorf("the call gave up after %s, before its own deadline", elapsed)
	}
	if elapsed > deadlineDelay*20 {
		t.Errorf("the call waited %s for an exchange that ignores the context", elapsed)
	}
	if calls() != 0 {
		t.Errorf("the far side ran for a call that never reached it")
	}
}

func TestCallDeadlineStillAcceptsAnAnswerThatArrivedInTime(t *testing.T) {
	respond, _ := responderFor(t)
	prompt := func(ctx context.Context, requestBytes []byte) ([]byte, error) {
		return respond(requestBytes)
	}
	caller := deadlineClient(t, 5*time.Second)
	prepared, err := caller.BuildRequest(context.Background(), testPublicKey(t, "bob"), mustObject(t, `{"op":"ping"}`), core.BuildRequestOptions{})
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	outcome, err := caller.Send(context.Background(), prepared, prompt)
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	if !outcome.OK {
		t.Errorf("got %+v, want a success", outcome.Error)
	}
}

func TestCallerCancellationIsAnAbortNotATimeout(t *testing.T) {
	respond, _ := responderFor(t)
	stubborn := func(ctx context.Context, requestBytes []byte) ([]byte, error) {
		select {
		case <-time.After(10 * time.Second):
			return respond(requestBytes)
		}
	}
	caller := deadlineClient(t, 5*time.Second)
	prepared, err := caller.BuildRequest(context.Background(), testPublicKey(t, "bob"), mustObject(t, `{"op":"ping"}`), core.BuildRequestOptions{})
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(5 * time.Millisecond)
		cancel()
	}()
	_, err = caller.Send(ctx, prepared, stubborn)
	if code := core.CodeOf(err); code != core.ErrCallAborted {
		t.Errorf("got %q, want ERR_CALL_ABORTED", code)
	}
}

func TestCallDoesNotLeaveAGoroutineBehind(t *testing.T) {
	// The exchange is still parked when the caller has gone, and it must be able
	// to finish without blocking on a channel nobody reads.
	respond, _ := responderFor(t)
	released := make(chan struct{})
	stubborn := func(ctx context.Context, requestBytes []byte) ([]byte, error) {
		<-released
		return respond(requestBytes)
	}
	caller := deadlineClient(t, deadlineDelay)
	prepared, err := caller.BuildRequest(context.Background(), testPublicKey(t, "bob"), mustObject(t, `{"op":"ping"}`), core.BuildRequestOptions{})
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	if _, err := caller.Send(context.Background(), prepared, stubborn); core.CodeOf(err) != core.ErrCallTimeout {
		t.Fatalf("got %q, want ERR_CALL_TIMEOUT", core.CodeOf(err))
	}
	// Releasing it must not block, which it would if the result channel were
	// unbuffered.
	close(released)
	time.Sleep(50 * time.Millisecond)
}
