// LOGZ.IO GRAFANA CHANGE :: DEV-18005 - add requestId in error message
package es

import (
	// "bytes"
	"encoding/json"
	// "io/ioutil"
	"net/http"
	"time"
)

// ErrorResponse represents an error response
type ErrorResponse struct {
	ErrorCode string `json:"errorCode,omitempty"`
	Code      int    `json:"code,omitempty"`
	Message   string `json:"message"`
	RequestId string `json:"requestId"`
}

func (c *baseClientImpl) DecodeErrorResponse(res *http.Response) (*ErrorResponse, error) {
	defer res.Body.Close()

	start := time.Now()
	c.logger.Debug("Decoding error json response")
	// removed because debugEnabled was removed: https://github.com/grafana/grafana/pull/59712
	// var bodyBytes []byte
	// if c.debugEnabled {
	// 	tmpBytes, err := ioutil.ReadAll(res.Body)
	// 	if err != nil {
	// 		c.logger.Error("failed to read http response bytes", "error", err)
	// 	} else {
	// 		bodyBytes = make([]byte, len(tmpBytes))
	// 		copy(bodyBytes, tmpBytes)
	// 		res.Body = ioutil.NopCloser(bytes.NewBuffer(tmpBytes))
	// 	}
	// }

	var errorResponse ErrorResponse
	dec := json.NewDecoder(res.Body)
	err := dec.Decode(&errorResponse)
	if err != nil {
		return nil, err
	}
	elapsed := time.Since(start)
	c.logger.Debug("Decoded error json response", "took", elapsed)

	return &errorResponse, err
}

// LOGZ.IO GRAFANA CHANGE :: end
