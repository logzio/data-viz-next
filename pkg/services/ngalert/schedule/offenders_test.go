// LOGZ.IO GRAFANA CHANGE :: APPZ-3027: Tests for bounded top-N offender reporting.
package schedule

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func byResults(a, b offender) bool { return a.results > b.results }

func TestOffenderTracker_KeepsWorstPerRule(t *testing.T) {
	tr := newOffenderTracker(byResults)

	// The same rule seen repeatedly must occupy exactly one slot, holding its worst
	// sample, so a frequently evaluated rule cannot crowd out the rest of the report.
	tr.observe(offender{ruleUID: "a", results: 10})
	tr.observe(offender{ruleUID: "a", results: 900})
	tr.observe(offender{ruleUID: "a", results: 50})
	tr.observe(offender{ruleUID: "b", results: 100})

	got, seen := tr.drain(10)
	require.Len(t, got, 2)
	assert.EqualValues(t, 4, seen, "every observation counts toward the denominator")
	assert.Equal(t, "a", got[0].ruleUID)
	assert.Equal(t, 900, got[0].results, "worst sample for the rule is retained, not the latest")
	assert.Equal(t, "b", got[1].ruleUID)
}

func TestOffenderTracker_ExactTopNRegardlessOfArrivalOrder(t *testing.T) {
	// Ascending arrival is the case a threshold-based top-N slice gets wrong: early
	// small samples set the bar and later large ones can be rejected.
	ascending := newOffenderTracker(byResults)
	for i := 1; i <= 500; i++ {
		ascending.observe(offender{ruleUID: fmt.Sprintf("rule-%d", i), results: i})
	}
	got, seen := ascending.drain(3)
	require.Len(t, got, 3)
	assert.EqualValues(t, 500, seen)
	assert.Equal(t, []int{500, 499, 498}, []int{got[0].results, got[1].results, got[2].results})

	descending := newOffenderTracker(byResults)
	for i := 500; i >= 1; i-- {
		descending.observe(offender{ruleUID: fmt.Sprintf("rule-%d", i), results: i})
	}
	got2, _ := descending.drain(3)
	require.Len(t, got2, 3)
	assert.Equal(t, []int{500, 499, 498}, []int{got2[0].results, got2[1].results, got2[2].results},
		"result must not depend on arrival order")
}

func TestOffenderTracker_DrainResetsWindow(t *testing.T) {
	tr := newOffenderTracker(byResults)
	tr.observe(offender{ruleUID: "a", results: 42})

	got, seen := tr.drain(10)
	require.Len(t, got, 1)
	require.EqualValues(t, 1, seen)

	// The drain interval is the only expiry mechanism, so nothing may survive it.
	got, seen = tr.drain(10)
	assert.Empty(t, got)
	assert.EqualValues(t, 0, seen)
}

func TestOffenderReporter_TracksBothAxesIndependently(t *testing.T) {
	r := newOffenderReporter(nil, 1, time.Minute)

	// Heaviest by result count and slowest to process are different rules; a report
	// limited to one entry per axis must surface both.
	r.observe(offender{ruleUID: "wide", results: 900_000, procDur: time.Second})
	r.observe(offender{ruleUID: "slow", results: 5, procDur: 11 * time.Minute})

	byRes, seen := r.byResults.drain(1)
	byDur, _ := r.byProcDur.drain(1)
	require.Len(t, byRes, 1)
	require.Len(t, byDur, 1)
	assert.EqualValues(t, 2, seen)
	assert.Equal(t, "wide", byRes[0].ruleUID)
	assert.Equal(t, "slow", byDur[0].ruleUID)
}

func TestOffenderReporter_NilIsSafe(t *testing.T) {
	// schedule structs built directly in tests leave the reporter nil.
	var r *offenderReporter
	assert.NotPanics(t, func() {
		r.observe(offender{ruleUID: "a", results: 1})
		r.report()
	})
}

func TestOffenderReporter_ReportEmptyWindowDoesNotPanicWithNilLogger(t *testing.T) {
	// A window with no evaluations must return before touching the logger.
	r := newOffenderReporter(nil, 10, time.Minute)
	assert.NotPanics(t, r.report)
}

// LOGZ.IO GRAFANA CHANGE :: End
