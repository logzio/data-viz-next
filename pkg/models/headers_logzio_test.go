package models

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGetDatasourceQueryHeaders(t *testing.T) {
	logzHeaders := http.Header{}
	logzHeaders.Set("Query-Source", "METRICS_ALERTS")
	logzHeaders.Set("x-gf-rule-uid", "rule-abc")
	logzHeaders.Set("x-gf-rule-group", "group-1")
	logzHeaders.Set("x-gf-rule-title", "High CPU")
	logzHeaders.Set("x-not-whitelisted", "should-not-forward")

	lh := &LogzIoHeaders{RequestHeaders: logzHeaders}
	out := lh.GetDatasourceQueryHeaders(http.Header{})

	// Whitelisted headers (including the alert-rule identity headers) are forwarded to the datasource request.
	require.Equal(t, "METRICS_ALERTS", out.Get("Query-Source"))
	require.Equal(t, "rule-abc", out.Get("x-gf-rule-uid"))
	require.Equal(t, "group-1", out.Get("x-gf-rule-group"))
	require.Equal(t, "High CPU", out.Get("x-gf-rule-title"))

	// Non-whitelisted headers are not forwarded.
	require.Empty(t, out.Get("x-not-whitelisted"))
}
