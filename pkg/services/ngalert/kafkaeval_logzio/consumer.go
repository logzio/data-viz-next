// LOGZ.IO GRAFANA CHANGE :: APPZ-3298 Kafka-direct alert evaluation
//
// Package kafkaeval consumes per-rule alert evaluation messages produced by metrics-alerts
// (key = rule id) and hands each one to the scheduler exactly like the eval HTTP endpoint does.
// Kafka partition ownership pins a rule to one evaluator pod, replacing the accidental ALB
// stickiness of the HTTP path. Fork-only package, wired in ngalert.go behind
// [unified_alerting] evaluation_kafka_enabled.
package kafkaeval

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/twmb/franz-go/pkg/kgo"

	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/models"
	ngmodels "github.com/grafana/grafana/pkg/services/ngalert/models"
	"github.com/grafana/grafana/pkg/services/ngalert/schedule"
	"github.com/grafana/grafana/pkg/setting"
)

const (
	// supportedSchemaVersion is the cross-repo message contract with the metrics-alerts producer
	// (AlertRuleEvaluationMessage in gaia-full); bump both sides together.
	supportedSchemaVersion = 1
	// evalSmearSeconds mirrors the HTTP eval path: spread a batch over up to 30s so one poll's
	// worth of rules does not hit the datasource at once.
	evalSmearSeconds = 30
	handoffTimeout   = 30 * time.Second
)

// evaluationMessage is the wire format of one evaluation. alertRule is the same JSON the HTTP
// eval path carries in AlertEvaluationRequest, so it decodes into the same struct.
type evaluationMessage struct {
	SchemaVersion int                `json:"schemaVersion"`
	AccountID     int64              `json:"accountId"`
	UserContext   string             `json:"userContext"`
	EvalTime      time.Time          `json:"evalTime"`
	FolderTitle   string             `json:"folderTitle"`
	AlertRule     ngmodels.AlertRule `json:"alertRule"`
}

type Consumer struct {
	log      log.Logger
	schedule schedule.ScheduleService
	metrics  *consumerMetrics

	brokers    []string
	topic      string
	groupID    string
	instanceID string
	staleness  time.Duration

	// Seams for tests: fixed clock, synchronous smear.
	now       func() time.Time
	afterFunc func(time.Duration, func()) *time.Timer
}

func NewConsumer(cfg *setting.Cfg, sched schedule.ScheduleService, registerer prometheus.Registerer, logger log.Logger) (*Consumer, error) {
	ua := cfg.UnifiedAlerting
	if ua.EvaluationKafkaBrokers == "" {
		return nil, errors.New("kafkaeval: evaluation_kafka_brokers must not be empty")
	}
	brokers := strings.Split(ua.EvaluationKafkaBrokers, ",")
	for i := range brokers {
		brokers[i] = strings.TrimSpace(brokers[i])
	}
	return &Consumer{
		log:        logger,
		schedule:   sched,
		metrics:    newConsumerMetrics(registerer),
		brokers:    brokers,
		topic:      ua.EvaluationKafkaTopic,
		groupID:    ua.EvaluationKafkaGroupID,
		instanceID: ua.EvaluationKafkaInstanceID,
		staleness:  time.Duration(ua.EvaluationKafkaStalenessHours) * time.Hour,
		now:        time.Now,
		afterFunc:  time.AfterFunc,
	}, nil
}

// Run polls until the context is canceled. Offsets are committed after a batch is handed off to
// the rule routines, not after evaluation: a monster rule can evaluate for minutes and must not
// block its partition peers. The cron re-produces every rule each tick, so the loss window of a
// crash between handoff and evaluation is one tick.
func (c *Consumer) Run(ctx context.Context) error {
	client, err := c.newClient()
	if err != nil {
		return fmt.Errorf("kafkaeval: failed to create kafka client: %w", err)
	}
	defer client.Close()

	c.log.Info("Starting Kafka evaluation consumer",
		"brokers", strings.Join(c.brokers, ","), "topic", c.topic, "group", c.groupID,
		"instance", c.instanceID, "staleness", c.staleness)

	for {
		fetches := client.PollFetches(ctx)
		if fetches.IsClientClosed() || ctx.Err() != nil {
			c.log.Info("Kafka evaluation consumer stopped")
			return nil
		}
		fetches.EachError(func(topic string, partition int32, err error) {
			if !errors.Is(err, context.Canceled) {
				c.log.Error("Kafka fetch error", "topic", topic, "partition", partition, "error", err)
			}
		})

		records := fetches.Records()
		if len(records) == 0 {
			continue
		}
		c.handleBatch(records)

		if err := client.CommitUncommittedOffsets(ctx); err != nil && !errors.Is(err, context.Canceled) {
			c.log.Error("Failed to commit Kafka offsets", "error", err)
		}
	}
}

func (c *Consumer) newClient() (*kgo.Client, error) {
	opts := []kgo.Opt{
		kgo.SeedBrokers(c.brokers...),
		kgo.ConsumeTopics(c.topic),
		kgo.ConsumerGroup(c.groupID),
		kgo.ClientID("grafana-x-alerts-evaluator"),
		// Cooperative-sticky keeps partition movement minimal on deploys; a moved rule re-warms
		// via targeted warm (APPZ-3028) before its next evaluation.
		kgo.Balancers(kgo.CooperativeStickyBalancer()),
		kgo.DisableAutoCommit(),
		// Matches the HTTP-path consumer: a fresh group starts at the tip, the cron replays
		// everything within one tick anyway.
		kgo.ConsumeResetOffset(kgo.NewOffset().AtEnd()),
		kgo.WithLogger(kgoLogger{log: c.log}),
	}
	if c.instanceID != "" {
		// Static membership: a pod restart within the session timeout does not rebalance.
		opts = append(opts, kgo.InstanceID(c.instanceID))
	}
	return kgo.NewClient(opts...)
}

// handleBatch decodes a poll's records, drops stale evaluations, keeps only the newest evaluation
// per rule (a backlog drains in seconds instead of replaying every tick) and hands the rest off.
func (c *Consumer) handleBatch(records []*kgo.Record) {
	cutoff := c.now().Add(-c.staleness)
	latest := make(map[ngmodels.AlertRuleKey]*evaluationMessage, len(records))
	var decodeFailures, unsupportedSchema, skippedStale, coalescedDropped int

	for _, record := range records {
		var msg evaluationMessage
		if err := json.Unmarshal(record.Value, &msg); err != nil {
			decodeFailures++
			c.log.Error("Failed to decode evaluation message", "partition", record.Partition, "offset", record.Offset, "error", err)
			continue
		}
		if msg.SchemaVersion != supportedSchemaVersion {
			unsupportedSchema++
			c.log.Error("Unsupported evaluation message schema", "schema_version", msg.SchemaVersion, "partition", record.Partition, "offset", record.Offset)
			continue
		}
		if msg.EvalTime.Before(cutoff) {
			skippedStale++
			continue
		}
		key := ngmodels.AlertRuleKey{OrgID: msg.AlertRule.OrgID, UID: msg.AlertRule.UID}
		if existing, ok := latest[key]; ok {
			coalescedDropped++
			if !msg.EvalTime.After(existing.EvalTime) {
				continue
			}
		}
		keep := msg
		latest[key] = &keep
	}

	for _, msg := range latest {
		c.handoff(msg)
	}

	c.metrics.consumed.Add(float64(len(records)))
	c.metrics.decodeFailures.Add(float64(decodeFailures))
	c.metrics.unsupportedSchema.Add(float64(unsupportedSchema))
	c.metrics.skippedStale.Add(float64(skippedStale))
	c.metrics.coalescedDropped.Add(float64(coalescedDropped))
	c.metrics.handoffs.Add(float64(len(latest)))
	c.log.Debug("Handled evaluation batch", "records", len(records), "handed_off", len(latest),
		"decode_failures", decodeFailures, "unsupported_schema", unsupportedSchema,
		"skipped_stale", skippedStale, "coalesced_dropped", coalescedDropped)
}

// handoff schedules one evaluation on the rule's routine, smeared like the HTTP path. The rule
// routine must already exist (the scheduler's tick registers rules from the database); a message
// for a rule created after the last tick fails here and the next tick heals it.
func (c *Consumer) handoff(msg *evaluationMessage) {
	requestID := uuid.NewString()
	evalReq := ngmodels.ExternalAlertEvaluationRequest{
		AlertRule:   msg.AlertRule,
		EvalTime:    msg.EvalTime,
		FolderTitle: msg.FolderTitle,
		LogzHeaders: c.buildHeaders(msg, requestID),
	}

	c.log.Info("Evaluate Alert Kafka", "eval_time", msg.EvalTime, "rule_title", msg.AlertRule.Title,
		"rule_uid", msg.AlertRule.UID, "org_id", msg.AlertRule.OrgID, "requestId", requestID)

	step := time.Duration(msg.AlertRule.ID%evalSmearSeconds) * time.Second
	ruleTitle, ruleUID, orgID := msg.AlertRule.Title, msg.AlertRule.UID, msg.AlertRule.OrgID
	c.afterFunc(step, func() {
		ctx, cancel := context.WithTimeout(context.Background(), handoffTimeout)
		defer cancel()
		if err := c.schedule.RunRuleEvaluation(ctx, evalReq); err != nil {
			c.metrics.handoffFailures.Inc()
			c.log.Error("Failed to run rule evaluation", "error", err, "rule_title", ruleTitle,
				"rule_uid", ruleUID, "org_id", orgID, "requestId", requestID)
		}
	})
}

// buildHeaders recreates the headers the HTTP path forwards to the datasource query
// (models.logzioHeadersWhitelist): the prebuilt user context from the message, the query source
// and a generated request id.
func (c *Consumer) buildHeaders(msg *evaluationMessage, requestID string) http.Header {
	headers := http.Header{}
	headers.Set("user-context", msg.UserContext)
	headers.Set("Logzio-Account-Id", strconv.FormatInt(msg.AccountID, 10))
	headers.Set("Query-Source", "METRICS_ALERTS")
	headers.Set(models.LogzioRequestIdHeaderName, requestID)
	return headers
}

type consumerMetrics struct {
	consumed          prometheus.Counter
	decodeFailures    prometheus.Counter
	unsupportedSchema prometheus.Counter
	skippedStale      prometheus.Counter
	coalescedDropped  prometheus.Counter
	handoffs          prometheus.Counter
	handoffFailures   prometheus.Counter
}

func newConsumerMetrics(registerer prometheus.Registerer) *consumerMetrics {
	counter := func(name, help string) prometheus.Counter {
		c := prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: "grafana",
			Subsystem: "alerting",
			Name:      name,
			Help:      help,
		})
		registerer.MustRegister(c)
		return c
	}
	return &consumerMetrics{
		consumed:          counter("logzio_kafka_eval_consumed_total", "Evaluation messages consumed from Kafka."),
		decodeFailures:    counter("logzio_kafka_eval_decode_failures_total", "Evaluation messages that failed to decode."),
		unsupportedSchema: counter("logzio_kafka_eval_unsupported_schema_total", "Evaluation messages with an unsupported schema version."),
		skippedStale:      counter("logzio_kafka_eval_skipped_stale_total", "Evaluation messages dropped for exceeding the staleness window."),
		coalescedDropped:  counter("logzio_kafka_eval_coalesced_dropped_total", "Older duplicate evaluations dropped in favor of a newer one for the same rule."),
		handoffs:          counter("logzio_kafka_eval_handoffs_total", "Evaluations handed off to rule routines."),
		handoffFailures:   counter("logzio_kafka_eval_handoff_failures_total", "Evaluations the scheduler refused, usually a rule not yet registered."),
	}
}

// kgoLogger adapts the grafana logger to the franz-go logging interface.
type kgoLogger struct {
	log log.Logger
}

func (l kgoLogger) Level() kgo.LogLevel {
	return kgo.LogLevelInfo
}

func (l kgoLogger) Log(level kgo.LogLevel, msg string, keyvals ...any) {
	switch level {
	case kgo.LogLevelError:
		l.log.Error(msg, keyvals...)
	case kgo.LogLevelWarn:
		l.log.Warn(msg, keyvals...)
	case kgo.LogLevelDebug:
		l.log.Debug(msg, keyvals...)
	default:
		l.log.Info(msg, keyvals...)
	}
}

// LOGZ.IO GRAFANA CHANGE :: End
