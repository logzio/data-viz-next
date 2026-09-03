// LOGZ.IO GRAFANA CHANGE :: APPZ-3298 Kafka-direct alert evaluation
package kafkaeval

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/twmb/franz-go/pkg/kgo"

	"github.com/grafana/grafana/pkg/infra/log"
	ngmodels "github.com/grafana/grafana/pkg/services/ngalert/models"
)

var testNow = time.Date(2026, 9, 2, 10, 0, 0, 0, time.UTC)

type fakeSchedule struct {
	mu   sync.Mutex
	reqs []ngmodels.ExternalAlertEvaluationRequest
	err  error
}

func (f *fakeSchedule) Run(_ context.Context) error {
	return nil
}

func (f *fakeSchedule) RunRuleEvaluation(_ context.Context, evalReq ngmodels.ExternalAlertEvaluationRequest) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reqs = append(f.reqs, evalReq)
	return f.err
}

func (f *fakeSchedule) requests() []ngmodels.ExternalAlertEvaluationRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]ngmodels.ExternalAlertEvaluationRequest{}, f.reqs...)
}

func newTestConsumer(t *testing.T, sched *fakeSchedule) *Consumer {
	t.Helper()
	return &Consumer{
		log:       log.NewNopLogger(),
		schedule:  sched,
		metrics:   newConsumerMetrics(prometheus.NewRegistry()),
		staleness: 3 * time.Hour,
		now:       func() time.Time { return testNow },
		afterFunc: func(_ time.Duration, f func()) *time.Timer {
			f()
			return time.NewTimer(0)
		},
	}
}

func record(t *testing.T, overrides map[string]any) *kgo.Record {
	t.Helper()
	payload := map[string]any{
		"schemaVersion": supportedSchemaVersion,
		"accountId":     123,
		"userContext":   `{"accountId":123}`,
		"evalTime":      testNow.Format(time.RFC3339),
		"folderTitle":   "Folder A",
		"alertRule": map[string]any{
			"id":    int64(7),
			"orgId": int64(10),
			"uid":   "uid7",
			"title": "rule 7",
		},
	}
	for k, v := range overrides {
		payload[k] = v
	}
	value, err := json.Marshal(payload)
	require.NoError(t, err)
	return &kgo.Record{Value: value}
}

func TestHandleBatchHandsOffDecodedEvaluation(t *testing.T) {
	sched := &fakeSchedule{}
	c := newTestConsumer(t, sched)

	c.handleBatch([]*kgo.Record{record(t, nil)})

	reqs := sched.requests()
	require.Len(t, reqs, 1)
	req := reqs[0]
	assert.Equal(t, "uid7", req.AlertRule.UID)
	assert.Equal(t, int64(10), req.AlertRule.OrgID)
	assert.Equal(t, int64(7), req.AlertRule.ID)
	assert.Equal(t, "rule 7", req.AlertRule.Title)
	assert.Equal(t, "Folder A", req.FolderTitle)
	assert.True(t, req.EvalTime.Equal(testNow))
	assert.Equal(t, `{"accountId":123}`, req.LogzHeaders.Get("user-context"))
	assert.Equal(t, "123", req.LogzHeaders.Get("Logzio-Account-Id"))
	assert.Equal(t, "METRICS_ALERTS", req.LogzHeaders.Get("Query-Source"))
	assert.NotEmpty(t, req.LogzHeaders.Get("x-request-id"))
}

func TestHandleBatchDropsStaleAndBrokenMessages(t *testing.T) {
	sched := &fakeSchedule{}
	c := newTestConsumer(t, sched)

	stale := record(t, map[string]any{
		"evalTime": testNow.Add(-4 * time.Hour).Format(time.RFC3339),
	})
	wrongSchema := record(t, map[string]any{"schemaVersion": supportedSchemaVersion + 1})
	broken := &kgo.Record{Value: []byte("not json")}

	c.handleBatch([]*kgo.Record{stale, wrongSchema, broken})

	assert.Empty(t, sched.requests())
}

func TestHandleBatchKeepsNewestEvaluationPerRule(t *testing.T) {
	sched := &fakeSchedule{}
	c := newTestConsumer(t, sched)

	older := record(t, map[string]any{
		"evalTime": testNow.Add(-2 * time.Minute).Format(time.RFC3339),
	})
	newer := record(t, map[string]any{
		"evalTime": testNow.Add(-1 * time.Minute).Format(time.RFC3339),
	})
	otherRule := record(t, map[string]any{
		"alertRule": map[string]any{
			"id":    int64(8),
			"orgId": int64(10),
			"uid":   "uid8",
			"title": "rule 8",
		},
	})

	// Newest first proves coalescing picks the newest eval time, not the last record.
	c.handleBatch([]*kgo.Record{newer, older, otherRule})

	reqs := sched.requests()
	require.Len(t, reqs, 2)
	byUID := map[string]ngmodels.ExternalAlertEvaluationRequest{}
	for _, req := range reqs {
		byUID[req.AlertRule.UID] = req
	}
	require.Contains(t, byUID, "uid7")
	require.Contains(t, byUID, "uid8")
	assert.True(t, byUID["uid7"].EvalTime.Equal(testNow.Add(-1*time.Minute)))
}

func TestHandoffFailureIsCountedAndDoesNotPanic(t *testing.T) {
	sched := &fakeSchedule{err: errors.New("no rule routine")}
	c := newTestConsumer(t, sched)

	c.handleBatch([]*kgo.Record{record(t, nil)})

	require.Len(t, sched.requests(), 1)
}

// LOGZ.IO GRAFANA CHANGE :: End
