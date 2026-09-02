package state

// LOGZ.IO GRAFANA CHANGE :: APPZ-3028 Targeted state cache warm
//
// Replaces the per-tick full state cache reload when [unified_alerting] targeted_warm_enabled is
// on: the startup warm-up still loads everything once, a rule is re-warmed right before its
// evaluation after a gap in local evaluations, and an idle sweep frees the cached states of rules
// this pod does not evaluate (cache only, never the database). The full snapshot is still loaded
// every tick and fed to the state cache compare only, as the rollout observation window; that
// load (shadowWarmCompare) gets deleted once observation shows zero discrepancies. Behavioral by
// design, so not part of the observer. Reached through the Manager's Logzio delegate.

import (
	"context"
	"strconv"
	"time"

	"github.com/grafana/grafana-plugin-sdk-go/data"

	ngModels "github.com/grafana/grafana/pkg/services/ngalert/models"
)

const (
	// TargetedWarmReloadAfter is the local-evaluation gap after which a rule re-warms before evaluating.
	TargetedWarmReloadAfter = 5 * time.Minute
	// TargetedWarmEvictAfter is the idle threshold of the sweep. MUST exceed TargetedWarmReloadAfter,
	// so an evicted rule always re-warms before its next evaluation.
	TargetedWarmEvictAfter = 15 * time.Minute
)

type logzioTargetedWarm struct {
	enabled  bool
	manager  *Manager
	observer *logzioStateObserver
}

func newLogzioTargetedWarm(cfg ManagerCfg, manager *Manager, observer *logzioStateObserver) *logzioTargetedWarm {
	return &logzioTargetedWarm{
		enabled:  cfg.TargetedWarmEnabled,
		manager:  manager,
		observer: observer,
	}
}

// maintainCache is the per-tick maintenance: the original full reload, or sweep plus shadow compare.
func (w *logzioTargetedWarm) maintainCache(ctx context.Context, rulesReader RuleReader) {
	if !w.enabled {
		w.manager.Warm(ctx, rulesReader)
		return
	}
	w.shadowWarmCompare(ctx)
	w.sweepIdleRuleStates()
}

// warmRuleIfNeeded re-warms the rule when the mode is on, it is not paused, and it had no recent local evaluation.
func (w *logzioTargetedWarm) warmRuleIfNeeded(ctx context.Context, rule *ngModels.AlertRule) {
	if !w.enabled || rule.IsPaused {
		return
	}
	if w.manager.clock.Now().Sub(w.observer.lastRuleActivity(rule.GetKey())) <= TargetedWarmReloadAfter {
		return
	}
	w.warmRule(ctx, rule)
}

// warmRule replaces the rule's cached states with the persisted ones; on a database error the cache is kept.
func (w *logzioTargetedWarm) warmRule(ctx context.Context, rule *ngModels.AlertRule) {
	if w.manager.instanceStore == nil {
		w.manager.log.Info("Skip warming the rule state because instance store is not configured")
		return
	}
	logger := w.manager.log.FromContext(ctx)
	startTime := time.Now()

	cmd := ngModels.ListAlertInstancesQuery{
		RuleOrgID: rule.OrgID,
		RuleUID:   rule.UID,
	}
	alertInstances, err := w.manager.instanceStore.ListAlertInstances(ctx, &cmd)
	if err != nil {
		logger.Error("Unable to fetch the persisted states of the rule. Skip warming its state", "error", err, "rule_uid", rule.UID, "org_id", rule.OrgID)
		return
	}

	states := &ruleStates{states: make(map[string]*State, len(alertInstances))}
	for _, entry := range alertInstances {
		states.states[entryCacheID(w.manager, entry)] = entryToState(w.manager, entry, rule.Annotations)
	}
	w.manager.cache.setRuleStates(rule.OrgID, rule.UID, states)
	logger.Debug("Rule state cache has been warmed", "rule_uid", rule.UID, "org_id", rule.OrgID, "states", len(alertInstances), "duration", time.Since(startTime))
}

// sweepIdleRuleStates frees the cached states of rules with no local evaluation for TargetedWarmEvictAfter.
func (w *logzioTargetedWarm) sweepIdleRuleStates() {
	cutoff := w.manager.clock.Now().Add(-TargetedWarmEvictAfter)

	evictedRules := 0
	evictedStates := 0
	for _, key := range w.manager.cache.ruleKeys() {
		if w.observer.lastRuleActivity(key).After(cutoff) {
			continue
		}
		evictedStates += len(w.manager.cache.removeByRuleUID(key.OrgID, key.UID))
		evictedRules++
	}
	w.observer.ruleActivity.prune(cutoff)

	if evictedRules > 0 {
		w.manager.log.Info("Freed cached states of rules not evaluated on this pod", "rules", evictedRules, "states", evictedStates, "idle_threshold", TargetedWarmEvictAfter)
	}
}

// shadowWarmCompare loads the full snapshot, feeds it to the compare, and discards it without applying.
// Rollout scaffolding: delete this and its call once observation shows zero discrepancies.
func (w *logzioTargetedWarm) shadowWarmCompare(ctx context.Context) *stateCacheCompareSummary {
	if w.manager.instanceStore == nil {
		return nil
	}
	startTime := time.Now()

	orgIds, err := w.manager.instanceStore.FetchOrgIds(ctx)
	if err != nil {
		w.manager.log.Error("Shadow warm compare: unable to fetch orgIds", "error", err)
		return nil
	}

	snapshot := make(map[int64]map[string]*ruleStates, len(orgIds))
	for _, orgId := range orgIds {
		cmd := ngModels.ListAlertInstancesQuery{
			RuleOrgID: orgId,
		}
		alertInstances, err := w.manager.instanceStore.ListAlertInstances(ctx, &cmd)
		if err != nil {
			w.manager.log.Error("Shadow warm compare: unable to fetch alert instances", "error", err, "org_id", orgId)
			continue
		}
		orgStates := make(map[string]*ruleStates)
		snapshot[orgId] = orgStates
		for _, entry := range alertInstances {
			rs, ok := orgStates[entry.RuleUID]
			if !ok {
				rs = &ruleStates{states: make(map[string]*State)}
				orgStates[entry.RuleUID] = rs
			}
			rs.states[entryCacheID(w.manager, entry)] = entryToState(w.manager, entry, nil)
		}
	}

	summary := w.observer.compareSnapshotWithCache(snapshot)
	w.manager.log.Debug("Shadow warm compare finished", "duration", time.Since(startTime))
	return summary
}

// entryCacheID computes the cache key of a persisted alert instance, mirroring Warm.
func entryCacheID(st *Manager, entry *ngModels.AlertInstance) string {
	cacheID, err := entry.Labels.StringKey()
	if err != nil {
		st.log.Error("Error getting cacheId for entry", "error", err)
	}
	return cacheID
}

// entryToState converts a persisted alert instance into a cache State, mirroring Warm.
func entryToState(st *Manager, entry *ngModels.AlertInstance, annotations map[string]string) *State {
	var resultFp data.Fingerprint
	if entry.ResultFingerprint != "" {
		fp, err := strconv.ParseUint(entry.ResultFingerprint, 16, 64)
		if err != nil {
			st.log.Error("Failed to parse result fingerprint of alert instance", "error", err, "ruleUID", entry.RuleUID)
		}
		resultFp = data.Fingerprint(fp)
	}
	return &State{
		AlertRuleUID:         entry.RuleUID,
		OrgID:                entry.RuleOrgID,
		CacheID:              entryCacheID(st, entry),
		Labels:               map[string]string(entry.Labels),
		State:                translateInstanceState(entry.CurrentState),
		StateReason:          entry.CurrentReason,
		LastEvaluationString: "",
		StartsAt:             entry.CurrentStateSince,
		EndsAt:               entry.CurrentStateEnd,
		LastEvaluationTime:   entry.LastEvalTime,
		Annotations:          annotations,
		ResultFingerprint:    resultFp,
	}
}

// setRuleStates replaces the cached states of a single rule.
func (c *cache) setRuleStates(orgID int64, alertRuleUID string, states *ruleStates) {
	c.mtxStates.Lock()
	defer c.mtxStates.Unlock()
	orgStates, ok := c.states[orgID]
	if !ok {
		orgStates = make(map[string]*ruleStates)
		c.states[orgID] = orgStates
	}
	orgStates[alertRuleUID] = states
}

// ruleKeys returns the keys of all rules that currently have an entry in the cache.
func (c *cache) ruleKeys() []ngModels.AlertRuleKey {
	c.mtxStates.RLock()
	defer c.mtxStates.RUnlock()
	keys := make([]ngModels.AlertRuleKey, 0, len(c.states))
	for orgID, orgStates := range c.states {
		for uid := range orgStates {
			keys = append(keys, ngModels.AlertRuleKey{OrgID: orgID, UID: uid})
		}
	}
	return keys
}

// LOGZ.IO GRAFANA CHANGE :: End
