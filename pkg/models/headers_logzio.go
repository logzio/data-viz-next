// LOGZ.IO GRAFANA CHANGE :: DEV-43883 use LogzIoHeaders obj to pass on headers
package models

import (
	"net/http"
)

type LogzIoHeaders struct {
	RequestHeaders http.Header
}

var logzioHeadersWhitelist = []string{
	"user-context",
	"X-Logz-Query-Context",
	"Query-Source",
}

func (logzioHeaders *LogzIoHeaders) GetDatasourceQueryHeaders(grafanaGeneratedHeaders http.Header) http.Header {
	datasourceRequestHeaders := grafanaGeneratedHeaders.Clone()
	logzioGrafanaRequestHeaders := logzioHeaders.RequestHeaders

	for _, whitelistedHeader := range logzioHeadersWhitelist {
		if requestHeader := logzioGrafanaRequestHeaders.Get(whitelistedHeader); requestHeader != "" {
			if whitelistedHeader == "X-Logz-Query-Context" {
				datasourceRequestHeaders.Set("User-Context", requestHeader)
			} else {
				datasourceRequestHeaders.Set(whitelistedHeader, requestHeader)
			}
		}
	}

	return datasourceRequestHeaders
}

// LOGZ.IO GRAFANA CHANGE :: end
