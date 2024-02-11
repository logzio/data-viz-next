package api

// LOGZ.IO GRAFANA CHANGE :: DEV-30169,DEV-30170: add endpoints to evaluate and process alerts
import (
	"errors"
	"github.com/benbjohnson/clock"
	"github.com/grafana/grafana/pkg/util/errutil"

	//"github.com/grafana/grafana-plugin-sdk-go/data"
	"github.com/grafana/grafana/pkg/api/response"
	"github.com/grafana/grafana/pkg/cmd/grafana-cli/logger"
	"github.com/grafana/grafana/pkg/expr"
	"github.com/grafana/grafana/pkg/infra/log"
	contextmodel "github.com/grafana/grafana/pkg/services/contexthandler/model"
	"github.com/grafana/grafana/pkg/services/datasources"
	apimodels "github.com/grafana/grafana/pkg/services/ngalert/api/tooling/definitions"
	"github.com/grafana/grafana/pkg/services/ngalert/eval"
	ngmodels "github.com/grafana/grafana/pkg/services/ngalert/models"
	"github.com/grafana/grafana/pkg/services/ngalert/notifier"
	"github.com/grafana/grafana/pkg/services/ngalert/state"
	//"github.com/grafana/grafana/pkg/services/ngalert/store"
	"github.com/grafana/grafana/pkg/services/org"
	//"github.com/grafana/grafana/pkg/services/sqlstore/migrations/ualert"
	//"github.com/grafana/grafana/pkg/services/sqlstore/migrator"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/setting"
	"math"
	"net/http"
	//"net/url"
	"time"
)

const (
	EvaluationErrorRefIdKey = "REF_ID"
	QueryErrorType          = "QUERY_ERROR"
	OtherErrorType          = "OTHER"
)

type LogzioAlertingService struct {
	AlertingProxy *AlertingProxy
	Cfg           *setting.Cfg
	//AppUrl               *url.URL
	EvaluatorFactory     eval.EvaluatorFactory
	Clock                clock.Clock
	ExpressionService    *expr.Service
	StateManager         *state.Manager
	MultiOrgAlertmanager *notifier.MultiOrgAlertmanager
	//InstanceStore        store.InstanceStore
	Log log.Logger
	//Migrator             *migrator.Migrator
}

func NewLogzioAlertingService(
	Proxy *AlertingProxy,
	Cfg *setting.Cfg,
	EvaluatorFactory eval.EvaluatorFactory,
	Clock clock.Clock,
	//ExpressionService *expr.Service,
	//StateManager *state.Manager,
	MultiOrgAlertmanager *notifier.MultiOrgAlertmanager,
	//InstanceStore store.InstanceStore,
	log log.Logger,
	// SQLStore *sqlstore.SQLStore,
) *LogzioAlertingService {
	return &LogzioAlertingService{
		AlertingProxy: Proxy,
		Cfg:           Cfg,
		//AppUrl:               Cfg.ParsedAppURL,
		Clock:            Clock,
		EvaluatorFactory: EvaluatorFactory,
		//ExpressionService:    ExpressionService,
		//StateManager:         StateManager,
		MultiOrgAlertmanager: MultiOrgAlertmanager,
		//InstanceStore:        InstanceStore,
		Log: log,
		//Migrator:             SQLStore.BuildMigrator(),
	}
}

func (srv *LogzioAlertingService) RouteEvaluateAlert(c *contextmodel.ReqContext, evalRequest apimodels.AlertEvaluationRequest) response.Response {
	alertRuleToEvaluate := apiRuleToDbAlertRule(evalRequest.AlertRule)
	//condition := ngmodels.Condition{
	//	Condition: alertRuleToEvaluate.Condition,
	//	OrgID:     alertRuleToEvaluate.OrgID,
	//	Data:      alertRuleToEvaluate.Data,
	//}

	var dsOverrideByDsUid = map[string]ngmodels.EvaluationDatasourceOverride{}
	if evalRequest.DsOverrides != nil {
		for _, dsOverride := range evalRequest.DsOverrides {
			dsOverrideByDsUid[dsOverride.DsUid] = dsOverride
		}
	}

	start := srv.Clock.Now()

	logzioEvalContext := &ngmodels.LogzioAlertRuleEvalContext{
		LogzioHeaders:     c.Req.Header,
		DsOverrideByDsUid: dsOverrideByDsUid,
	}

	//ConditionEval(&condition, evalRequest.EvalTime, srv.ExpressionService, `&ngmodels.LogzioAlertRuleEvalContext{
	// 	LogzioHeaders:     httpReq.Header,`
	// 	DsOverrideByDsUid: dsOverrideByDsUid,
	// })
	//dur := srv.Clock.Now().Sub(start)
	//
	//if err != nil {
	//	srv.Log.Error("failed to evaluate alert rule", "duration", dur, "err", err, "ruleId", alertRuleToEvaluate.ID)
	//	return response.Error(http.StatusInternalServerError, "Failed to evaluate conditions", err)
	//}
	//

	// TODO: check if we want to use NewContextWithPreviousResults
	ctx := c.Req.Context()
	evalCtx := eval.NewContextWithLogzio(ctx, InternalUserFor(alertRuleToEvaluate.OrgID), logzioEvalContext)
	if srv.EvaluatorFactory == nil {
		panic("evalfactory nil")
	}
	ruleEval, err := srv.EvaluatorFactory.Create(evalCtx, alertRuleToEvaluate.GetEvalCondition())
	var results eval.Results
	var dur time.Duration
	if err != nil {
		dur = srv.Clock.Now().Sub(start)
		logger.Error("Failed to build rule evaluator", "error", err)
	} else {
		results, err = ruleEval.Evaluate(ctx, evalRequest.EvalTime)
		dur = srv.Clock.Now().Sub(start)
		if err != nil {
			logger.Error("Failed to evaluate rule", "error", err, "duration", dur)
		}
	}
	//
	//evalTotal.Inc()
	//evalDuration.Observe(dur.Seconds())

	//TODO: check if we want to add tracing ??
	if ctx.Err() != nil { // check if the context is not cancelled. The evaluation can be a long-running task.
		//span.SetStatus(codes.Error, "rule evaluation cancelled")
		logger.Debug("Skip updating the state because the context has been cancelled")
		return nil
	}

	if err != nil || results.HasErrors() {
		//evalTotalFailures.Inc()

		// TODO: make sure we don't want retry
		//// Only retry (return errors) if this isn't the last attempt, otherwise skip these return operations.
		//if retry {
		//	// The only thing that can return non-nil `err` from ruleEval.Evaluate is the server side expression pipeline.
		//	// This includes transport errors such as transient network errors.
		//	if err != nil {
		//		span.SetStatus(codes.Error, "rule evaluation failed")
		//		span.RecordError(err)
		//		return fmt.Errorf("server side expressions pipeline returned an error: %w", err)
		//	}
		//
		//	// If the pipeline executed successfully but have other types of errors that can be retryable, we should do so.
		//	if !results.HasNonRetryableErrors() {
		//		span.SetStatus(codes.Error, "rule evaluation failed")
		//		span.RecordError(err)
		//		return fmt.Errorf("the result-set has errors that can be retried: %w", results.Error())
		//	}
		//}

		// If results is nil, we assume that the error must be from the SSE pipeline (ruleEval.Evaluate) which is the only code that can actually return an `err`.
		if results == nil {
			results = append(results, eval.NewResultFromError(err, evalRequest.EvalTime, dur))
		}

		// If err is nil, we assume that the SSS pipeline succeeded and that the error must be embedded in the results.
		if err == nil {
			err = results.Error()
		}

		//span.SetStatus(codes.Error, "rule evaluation failed")
		//span.RecordError(err)
	} else {
		logger.Debug("Alert rule evaluated", "results", results, "duration", dur)
		//span.AddEvent("rule evaluated", trace.WithAttributes(
		//	attribute.Int64("results", int64(len(results))),
		//))
	}

	var apiEvalResults []apimodels.ApiEvalResult
	for _, result := range results {
		apiEvalResults = append(apiEvalResults, evaluationResultsToApi(result))
	}
	return response.JSON(http.StatusOK, apiEvalResults)

	///////////////////////// PROCESSING
	//start = sch.clock.Now()
	//processedStates := sch.stateManager.ProcessEvalResults(
	//	ctx,
	//	e.scheduledAt,
	//	e.rule,
	//	results,
	//	state.GetRuleExtraLabels(e.rule, e.folderTitle, !sch.disableGrafanaFolder),
	//)
	//processDuration.Observe(sch.clock.Now().Sub(start).Seconds())
	//
	//start = sch.clock.Now()
	//alerts := state.FromStateTransitionToPostableAlerts(processedStates, sch.stateManager, sch.appURL)
	//span.AddEvent("results processed", trace.WithAttributes(
	//	attribute.Int64("state_transitions", int64(len(processedStates))),
	//	attribute.Int64("alerts_to_send", int64(len(alerts.PostableAlerts))),
	//))
	//if len(alerts.PostableAlerts) > 0 {
	//	sch.alertsSender.Send(ctx, key, alerts)
	//}
	//sendDuration.Observe(sch.clock.Now().Sub(start).Seconds())
	//
	//return nil
}

//func (srv *LogzioAlertingService) RouteProcessAlert(httpReq http.Request, request apimodels.AlertProcessRequest) response.Response {
//	alertRule := apiRuleToDbAlertRule(request.AlertRule)
//
//	var shouldCreateAnnotationsAndAlertInstances bool
//	if request.ShouldManageAnnotationsAndInstances == nil {
//		shouldCreateAnnotationsAndAlertInstances = true
//	} else {
//		shouldCreateAnnotationsAndAlertInstances = *request.ShouldManageAnnotationsAndInstances
//	}
//
//	var evalResults eval.Results
//	for _, apiEvalResult := range request.EvaluationResults {
//		evalResults = append(evalResults, apiToEvaluationResult(apiEvalResult))
//	}
//
//	ctx := context.WithValue(httpReq.Context(), state.ShouldManageAnnotationsAndInstancesContextKey, shouldCreateAnnotationsAndAlertInstances)
//
//	processedStates := srv.StateManager.ProcessEvalResults(ctx, &alertRule, evalResults)
//	if shouldCreateAnnotationsAndAlertInstances {
//		srv.saveAlertStates(processedStates)
//	}
//
//	alerts := schedule.FromAlertStateToPostableAlerts(processedStates, srv.StateManager, srv.AppUrl)
//	for _, alert := range alerts.PostableAlerts {
//		alert.Annotations[ngmodels.LogzioAccountIdAnnotation] = request.AccountId
//	}
//
//	if len(alerts.PostableAlerts) > 0 {
//		n, err := srv.MultiOrgAlertmanager.AlertmanagerFor(alertRule.OrgID)
//		if err == nil {
//			srv.Log.Info("Pushing alerts to alert manager")
//			if err := n.PutAlerts(alerts); err != nil {
//				srv.Log.Error("failed to put alerts in the local notifier", "count", len(alerts.PostableAlerts), "err", err, "ruleId", alertRule.ID)
//				return response.Error(http.StatusInternalServerError, "Failed to process alert", err)
//			}
//		} else {
//			if errors.Is(err, notifier.ErrNoAlertmanagerForOrg) {
//				srv.Log.Info("local notifier was not found", "orgId", alertRule.OrgID)
//				return response.Error(http.StatusBadRequest, "Alert manager for organization not found", err)
//			} else {
//				srv.Log.Error("local notifier is not available", "err", err, "orgId", alertRule.OrgID)
//				return response.Error(http.StatusInternalServerError, "Failed to process alert", err)
//			}
//		}
//	} else {
//		srv.Log.Debug("no alerts to put in the notifier or to send to external Alertmanager(s)")
//	}
//
//	return response.JSONStreaming(http.StatusOK, alerts)
//}

func evaluationResultsToApi(evalResult eval.Result) apimodels.ApiEvalResult {
	apiEvalResult := apimodels.ApiEvalResult{
		Instance:           evalResult.Instance,
		State:              evalResult.State,
		StateName:          evalResult.State.String(),
		EvaluatedAt:        evalResult.EvaluatedAt,
		EvaluationDuration: evalResult.EvaluationDuration,
		EvaluationString:   evalResult.EvaluationString,
	}

	if evalResult.Values != nil {
		apiEvalResult.Values = make(map[string]apimodels.ApiNumberValueCapture, len(evalResult.Values))
		for k, v := range evalResult.Values {
			apiEvalResult.Values[k] = valueNumberCaptureToApi(v)
		}
	}

	if evalResult.Error != nil {
		errorMetadata := make(map[string]string)

		var queryError errutil.Error
		if errors.As(evalResult.Error, &queryError) &&
			errors.Is(evalResult.Error, expr.QueryError) {
			apiEvalResult.Error = &apimodels.ApiEvalError{
				Type:    QueryErrorType,
				Message: queryError.Error(),
			}

			errorMetadata[EvaluationErrorRefIdKey] = queryError.PublicPayload["refId"].(string) // TODO: validate this is returning expected value
		} else {
			apiEvalResult.Error = &apimodels.ApiEvalError{
				Type:    OtherErrorType,
				Message: evalResult.Error.Error(),
			}
		}

		apiEvalResult.Error.Metadata = errorMetadata
	}

	return apiEvalResult
}

//func apiToEvaluationResult(apiEvalResult apimodels.ApiEvalResult) eval.Result {
//	evalResult := eval.Result{
//		Instance:           apiEvalResult.Instance,
//		State:              apiEvalResult.State,
//		EvaluatedAt:        apiEvalResult.EvaluatedAt,
//		EvaluationDuration: apiEvalResult.EvaluationDuration,
//		EvaluationString:   apiEvalResult.EvaluationString,
//	}
//
//	if apiEvalResult.Values != nil {
//		evalResult.Values = make(map[string]eval.NumberValueCapture, len(apiEvalResult.Values))
//
//		for k, v := range apiEvalResult.Values {
//			evalResult.Values[k] = apiToNumberValueCapture(v)
//		}
//	}
//
//	if apiEvalResult.Error != nil {
//		if apiEvalResult.Error.Type == QueryErrorType {
//			errorMetadata := apiEvalResult.Error.Metadata
//			refId := errorMetadata[EvaluationErrorRefIdKey]
//
//			evalResult.Error = &expr.QueryError{
//				RefID: refId,
//				Err:   errors.New(apiEvalResult.Error.Message),
//			}
//		} else {
//			evalResult.Error = errors.New(apiEvalResult.Error.Message)
//		}
//	}
//
//	return evalResult
//}

func apiRuleToDbAlertRule(api apimodels.ApiAlertRule) ngmodels.AlertRule {
	return ngmodels.AlertRule{
		ID:              api.ID,
		OrgID:           api.OrgID,
		Title:           api.Title,
		Condition:       api.Condition,
		Data:            api.Data,
		Updated:         api.Updated,
		IntervalSeconds: api.IntervalSeconds,
		Version:         api.Version,
		UID:             api.UID,
		NamespaceUID:    api.NamespaceUID,
		DashboardUID:    api.DashboardUID,
		PanelID:         api.PanelID,
		RuleGroup:       api.RuleGroup,
		NoDataState:     api.NoDataState,
		ExecErrState:    api.ExecErrState,
		For:             api.For,
		Annotations:     api.Annotations,
		Labels:          api.Labels,
	}
}

//func apiToNumberValueCapture(api apimodels.ApiNumberValueCapture) eval.NumberValueCapture {
//	var evalValue *float64
//
//	if api.Value != nil {
//		apiValue := *api.Value
//		if api.IsNan {
//			apiValue = math.NaN()
//		}
//		evalValue = &apiValue
//	} else {
//		evalValue = nil
//	}
//
//	return eval.NumberValueCapture{
//		Var:    api.Var,
//		Labels: api.Labels,
//		Value:  evalValue,
//	}
//}

func valueNumberCaptureToApi(numberValueCapture eval.NumberValueCapture) apimodels.ApiNumberValueCapture {
	apiValue := numberValueCapture.Value
	isNan := false

	if numberValueCapture.Value != nil && math.IsNaN(*numberValueCapture.Value) {
		apiValue = nil
		isNan = true
	}

	return apimodels.ApiNumberValueCapture{
		Var:    numberValueCapture.Var,
		Labels: numberValueCapture.Labels,
		Value:  apiValue,
		IsNan:  isNan,
	}
}

//func (srv *LogzioAlertingService) saveAlertStates(states []*state.State) {
//	srv.Log.Debug("saving alert states", "count", len(states))
//	instances := make([]ngmodels.AlertInstance, 0, len(states))
//
//	type debugInfo struct {
//		OrgID  int64
//		Uid    string
//		State  string
//		Labels string
//	}
//	debug := make([]debugInfo, 0)
//
//	for _, s := range states {
//		labels := ngmodels.InstanceLabels(s.Labels)
//		_, hash, err := labels.StringAndHash()
//
//		if err != nil {
//			debug = append(debug, debugInfo{s.OrgID, s.AlertRuleUID, s.State.String(), s.Labels.String()})
//			srv.Log.Error("failed to save alert instance with invalid labels", "orgID", s.OrgID, "ruleUID", s.AlertRuleUID, "err", err)
//			continue
//		}
//		fields := ngmodels.AlertInstance{
//			AlertInstanceKey: ngmodels.AlertInstanceKey{
//				RuleOrgID:  s.OrgID,
//				RuleUID:    s.AlertRuleUID,
//				LabelsHash: hash,
//			},
//			Labels:            ngmodels.InstanceLabels(s.Labels),
//			CurrentState:      ngmodels.InstanceStateType(s.State.String()),
//			LastEvalTime:      s.LastEvaluationTime,
//			CurrentStateSince: s.StartsAt,
//			CurrentStateEnd:   s.EndsAt,
//		}
//		instances = append(instances, fields)
//	}
//
//	if err := srv.InstanceStore.SaveAlertInstances(context.Background(), instances...); err != nil {
//		for _, inst := range instances {
//			debug = append(debug, debugInfo{inst.RuleOrgID, inst.RuleUID, string(inst.CurrentState), data.Labels(inst.Labels).String()})
//		}
//		srv.Log.Error("failed to save alert states", "states", debug, "err", err)
//	}
//}

func InternalUserFor(orgID int64) *user.SignedInUser {
	return &user.SignedInUser{
		UserID:           -1,
		IsServiceAccount: true,
		Login:            "grafana_internal", // TODO: might need to create this ervice user so it can work ? or find one that can be used
		OrgID:            orgID,
		OrgRole:          org.RoleAdmin,
		Permissions: map[int64]map[string][]string{
			orgID: {
				datasources.ActionQuery: []string{
					datasources.ScopeAll,
				},
			},
		},
	}
}

// LOGZ.IO GRAFANA CHANGE :: end
