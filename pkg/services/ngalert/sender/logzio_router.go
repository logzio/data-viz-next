// LOGZ.IO GRAFANA CHANGE :: DEV-43744 Add logzio notification route
// This is an implementation for the AlertsSender interface.
// This implementation sends all notifications to logzio api to handle the notifications.
// This is basically like external alertmanager datasource, only it isn't customer configurable and only for notification,
// The alertmanager data (configuration) is still managed internally

package sender

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/services/ngalert/api/tooling/definitions"
	"github.com/grafana/grafana/pkg/services/ngalert/models"
	"io"
	"net/http"
)

type LogzioAlertsRouter struct {
	logger log.Logger
	client *http.Client
	url    string
}

func NewLogzioAlertsRouter(alertsRouteUrl string) (*LogzioAlertsRouter, error) {
	//TODO: understand how to config httpclient and from where
	client := http.DefaultClient

	return &LogzioAlertsRouter{
		logger: log.New("ngalert.sender.logzio_router"),
		client: client,
		url:    alertsRouteUrl,
	}, nil
}

func (d *LogzioAlertsRouter) Send(ctx context.Context, key models.AlertRuleKey, alerts definitions.PostableAlerts) {
	logger := d.logger.New(key.LogContext()...)
	logger.Debug("Sending alerts on logzio sender")
	if len(alerts.PostableAlerts) == 0 {
		logger.Info("No alerts to notify about")
		return
	}
	// TODO: add relevant headers if needed? or remove if not
	headers := make(map[string]string)
	payload, err := json.Marshal(alerts)
	if err != nil {
		logger.Error("Failed to marshal to json the alerts to send", "err", err)
		return
	}

	logger.Debug("Sending alerts", "url", d.url, "headers", headers, "alerts", alerts)
	err = sendOne(ctx, d.client, d.url, payload, headers)
	if err != nil {
		logger.Warn("Error from sending alerts to notify", "err", err)
	}

}

func sendOne(ctx context.Context, c *http.Client, url string, payload []byte, headers map[string]string) error {
	req, err := http.NewRequest("POST", url, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Content-Type", contentTypeJSON)
	// Extension: set headers.
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := c.Do(req.WithContext(ctx))
	if err != nil {
		return err
	}
	defer func() {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}()

	// Any HTTP status 2xx is OK.
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("bad response status %s", resp.Status)
	}

	return nil
}
