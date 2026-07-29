// LOGZ.IO GRAFANA CHANGE :: APPZ-3027: Replace per-rule_uid metric labels with bounded top-N offender reporting.
//
// Per-rule latency histograms cost one metric child per rule UID that is never
// released when a rule is deleted, which dominated the /metrics payload while
// still not recording the number that actually matters: how many results a
// single evaluation produced. This reports the heaviest evaluations to the log
// instead, at a cost bounded by the number of rules rather than by the number of
// evaluations.
package schedule

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/benbjohnson/clock"

	"github.com/grafana/grafana/pkg/infra/log"
)

const (
	// offenderReportInterval is how often the heaviest evaluations are logged.
	// Draining on this interval doubles as the expiry for tracked samples, so
	// there is no TTL to configure.
	//
	// The window has to be wide enough that a rule lands in most of them. The
	// heaviest rules take minutes to process and so self-throttle to roughly one
	// evaluation per 15 minutes, which would leave them absent from many windows if
	// the interval were shorter.
	offenderReportInterval = 15 * time.Minute

	// offenderReportSize is how many rules are reported per ordering. The top 100
	// rules account for ~40% of all evaluation cost, against ~20% for the top 12,
	// so a larger report shows the shape of the distribution and surfaces a new
	// offender well before it reaches the very top.
	offenderReportSize = 100
)

// offender is the single heaviest evaluation observed for one alert rule within
// the current reporting window.
type offender struct {
	ruleUID     string
	orgID       int64
	results     int
	transitions int
	evalDur     time.Duration
	procDur     time.Duration
}

// offenderTracker keeps, per alert rule, the worst evaluation seen since the
// last drain according to a single ordering.
//
// Keying by rule UID rather than keeping a sorted top-N slice means dedup comes
// for free (one hot rule cannot occupy every slot), the result is an exact top-N
// rather than one biased by arrival order, and the only sorting happens once per
// drain. Memory is bounded by the number of rules that evaluated in the window.
type offenderTracker struct {
	mu    sync.Mutex
	worse func(a, b offender) bool
	worst map[string]offender
	seen  int64
}

func newOffenderTracker(worse func(a, b offender) bool) *offenderTracker {
	return &offenderTracker{worse: worse, worst: make(map[string]offender)}
}

func (t *offenderTracker) observe(s offender) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.seen++
	if prev, ok := t.worst[s.ruleUID]; ok && !t.worse(s, prev) {
		return
	}
	t.worst[s.ruleUID] = s
}

// drain returns the n worst samples and the number of evaluations observed,
// resetting the tracker for the next window.
func (t *offenderTracker) drain(n int) ([]offender, int64) {
	t.mu.Lock()
	all, seen := t.worst, t.seen
	t.worst, t.seen = make(map[string]offender, len(all)), 0
	t.mu.Unlock()

	out := make([]offender, 0, len(all))
	for _, o := range all {
		out = append(out, o)
	}
	sort.Slice(out, func(i, j int) bool { return t.worse(out[i], out[j]) })
	if len(out) > n {
		out = out[:n]
	}
	return out, seen
}

// offenderReporter tracks the heaviest evaluations on two independent axes - the
// number of results produced, which drives memory, and the time spent turning
// those results into state, which drives latency - and periodically logs both.
type offenderReporter struct {
	byResults *offenderTracker
	byProcDur *offenderTracker
	size      int
	interval  time.Duration
	log       log.Logger
}

func newOffenderReporter(logger log.Logger, size int, interval time.Duration) *offenderReporter {
	return &offenderReporter{
		byResults: newOffenderTracker(func(a, b offender) bool { return a.results > b.results }),
		byProcDur: newOffenderTracker(func(a, b offender) bool { return a.procDur > b.procDur }),
		size:      size,
		interval:  interval,
		log:       logger,
	}
}

func (r *offenderReporter) observe(s offender) {
	if r == nil {
		return
	}
	r.byResults.observe(s)
	r.byProcDur.observe(s)
}

func (r *offenderReporter) run(ctx context.Context, c clock.Clock) {
	if r == nil || r.interval <= 0 {
		return
	}
	t := c.Ticker(r.interval)
	defer t.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			r.report()
		}
	}
}

// rankedOffender is one rule's entry in a report, carrying its position on each
// axis. A rank of 0 means the rule did not place on that axis.
type rankedOffender struct {
	offender
	resultsRank int
	procRank    int
}

// report logs the current window's heaviest evaluations and starts a new window.
func (r *offenderReporter) report() {
	if r == nil {
		return
	}

	byResults, seen := r.byResults.drain(r.size)
	byProcDur, _ := r.byProcDur.drain(r.size)
	if seen == 0 {
		return
	}

	// A rule that places on both axes is reported once, carrying both ranks, so
	// the report costs at most 2*size lines and usually far fewer.
	union := make(map[string]*rankedOffender, len(byResults)+len(byProcDur))
	for i, o := range byResults {
		union[o.ruleUID] = &rankedOffender{offender: o, resultsRank: i + 1}
	}
	for i, o := range byProcDur {
		if e, ok := union[o.ruleUID]; ok {
			e.procRank = i + 1
			continue
		}
		union[o.ruleUID] = &rankedOffender{offender: o, procRank: i + 1}
	}

	out := make([]*rankedOffender, 0, len(union))
	for _, e := range union {
		out = append(out, e)
	}
	// Rules ranked by result count first, then those that only placed on duration.
	rank := func(e *rankedOffender) int {
		if e.resultsRank > 0 {
			return e.resultsRank
		}
		return r.size + 1 + e.procRank
	}
	sort.Slice(out, func(i, j int) bool { return rank(out[i]) < rank(out[j]) })

	r.log.Info("Alert rule evaluation offenders",
		"window", r.interval,
		"evaluations", seen,
		"reported", len(out))

	for _, e := range out {
		r.log.Info("Alert rule offender",
			"rule_uid", e.ruleUID,
			"org_id", e.orgID,
			"results", e.results,
			"transitions", e.transitions,
			"eval_ms", e.evalDur.Milliseconds(),
			"process_ms", e.procDur.Milliseconds(),
			"results_rank", e.resultsRank,
			"process_rank", e.procRank,
			"window_evaluations", seen)
	}
}

// LOGZ.IO GRAFANA CHANGE :: End
