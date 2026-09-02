package state

// LOGZ.IO GRAFANA CHANGE :: APPZ-3028 Logzio delegate
//
// The single entry point for everything logzio adds to the state domain. The Manager holds one
// field (Logzio) and all upstream one-liners go through this type: observation hooks forward to
// the observer, behavioral entry points forward to the targeted-warm component.

import (
	"context"
	"time"

	ngModels "github.com/grafana/grafana/pkg/services/ngalert/models"
)

type LogzioDelegate struct {
	observer     *logzioStateObserver
	targetedWarm *logzioTargetedWarm
}

func newLogzioDelegate(cfg ManagerCfg, manager *Manager) *LogzioDelegate {
	observer := newLogzioStateObserver(cfg.Log, cfg.Clock, manager.cache)
	return &LogzioDelegate{
		observer:     observer,
		targetedWarm: newLogzioTargetedWarm(cfg, manager, observer),
	}
}

// ---- Observation hooks, one per upstream call site ----

// onRuleEvaluated is called by ProcessEvalResults for every evaluation this pod performs.
func (d *LogzioDelegate) onRuleEvaluated(key ngModels.AlertRuleKey, evaluatedAt time.Time) {
	d.observer.onRuleEvaluated(key, evaluatedAt)
}

// onWarmSnapshotLoaded is called by Warm with the loaded snapshot, right before it replaces the cache.
func (d *LogzioDelegate) onWarmSnapshotLoaded(snapshot map[int64]map[string]*ruleStates) {
	d.observer.onWarmSnapshotLoaded(snapshot)
}

// ---- Behavioral entry points, called by the scheduler ----

// MaintainCache runs the per-tick cache maintenance: full reload, or sweep plus shadow compare in targeted-warm mode.
func (d *LogzioDelegate) MaintainCache(ctx context.Context, rulesReader RuleReader) {
	d.targetedWarm.maintainCache(ctx, rulesReader)
}

// WarmRuleIfNeeded reloads a rule's states right before its evaluation when they may be stale.
func (d *LogzioDelegate) WarmRuleIfNeeded(ctx context.Context, rule *ngModels.AlertRule) {
	d.targetedWarm.warmRuleIfNeeded(ctx, rule)
}

// LOGZ.IO GRAFANA CHANGE :: End
