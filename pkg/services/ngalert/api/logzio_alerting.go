package api

// LOGZ.IO GRAFANA CHANGE :: DEV-30169,DEV-30170: add endpoints to evaluate and process alerts
import (
	"errors"
	"github.com/benbjohnson/clock"
	"github.com/grafana/grafana/pkg/services/ngalert/notifier"
	"github.com/grafana/grafana/pkg/services/ngalert/schedule"
	"github.com/grafana/grafana/pkg/util/errutil"
	"net/http"

	//"github.com/grafana/grafana-plugin-sdk-go/data"
	"github.com/grafana/grafana/pkg/api/response"
	"github.com/grafana/grafana/pkg/expr"
	"github.com/grafana/grafana/pkg/infra/log"
	contextmodel "github.com/grafana/grafana/pkg/services/contexthandler/model"
	"github.com/grafana/grafana/pkg/services/datasources"
	apimodels "github.com/grafana/grafana/pkg/services/ngalert/api/tooling/definitions"
	"github.com/grafana/grafana/pkg/services/ngalert/eval"
	ngmodels "github.com/grafana/grafana/pkg/services/ngalert/models"

	//"github.com/grafana/grafana/pkg/services/ngalert/store"
	"github.com/grafana/grafana/pkg/services/org"
	//"github.com/grafana/grafana/pkg/services/sqlstore/migrations/ualert"
	//"github.com/grafana/grafana/pkg/services/sqlstore/migrator"
	"github.com/grafana/grafana/pkg/services/user"
	"github.com/grafana/grafana/pkg/setting"
	"math"
)

const (
	EvaluationErrorRefIdKey = "REF_ID"
	QueryErrorType          = "QUERY_ERROR"
	OtherErrorType          = "OTHER"
)

type LogzioAlertingService struct {
	Cfg              *setting.Cfg
	EvaluatorFactory eval.EvaluatorFactory
	Clock            clock.Clock
	Log              log.Logger
	Schedule         schedule.ScheduleService
	//AlertingProxy 	  *AlertingProxy
	//ExpressionService *expr.Service
	//StateManager      *state.Manager
	//AppUrl               *url.URL
	MultiOrgAlertmanager *notifier.MultiOrgAlertmanager
	//InstanceStore        store.InstanceStore
	//Migrator             *migrator.Migrator
}

func NewLogzioAlertingService(
	Cfg *setting.Cfg,
	EvaluatorFactory eval.EvaluatorFactory,
	Clock clock.Clock,
	log log.Logger,
	Schedule schedule.ScheduleService,
	Proxy *AlertingProxy,
	MultiOrgAlertmanager *notifier.MultiOrgAlertmanager,
	// ExpressionService *expr.Service,
	// StateManager *state.Manager,
	// InstanceStore store.InstanceStore,
	// SQLStore *sqlstore.SQLStore,
) *LogzioAlertingService {
	return &LogzioAlertingService{
		Cfg:              Cfg,
		Clock:            Clock,
		EvaluatorFactory: EvaluatorFactory,
		Log:              log,
		Schedule:         Schedule,
		//AlertingProxy: Proxy,
		MultiOrgAlertmanager: MultiOrgAlertmanager,
		//AppUrl:               Cfg.ParsedAppURL,
		//ExpressionService:    ExpressionService,
		//StateManager:         StateManager,
		//InstanceStore:        InstanceStore,
		//Migrator:             SQLStore.BuildMigrator(),
	}
}

func (srv *LogzioAlertingService) RouteEvaluateAlert(c *contextmodel.ReqContext, evalRequest apimodels.AlertEvaluationRequest) response.Response {
	c.Logger.Info("Evaluate Alert API", "evalTime", evalRequest.EvalTime, "ruleTitle", evalRequest.AlertRule.Title, "ruleUID", evalRequest.AlertRule.UID)
	results, err := srv.Schedule.RunRuleEvaluation(c.Req.Context(), evalRequest)
	c.Logger.Info("Evaluate Alert API - Done", "evalTime", evalRequest.EvalTime, "ruleTitle", evalRequest.AlertRule.Title, "ruleUID", evalRequest.AlertRule.UID)

	if err != nil {
		srv.Log.Error("failed to run rule evaluation", "err", err)
		response.Error(http.StatusInternalServerError, "Failed to evaluate conditions", err)
	}
	var apiEvalResults []apimodels.ApiEvalResult
	for _, result := range results {
		apiEvalResults = append(apiEvalResults, evaluationResultsToApi(result))
	}
	return response.JSON(http.StatusOK, apiEvalResults)
}

func (srv *LogzioAlertingService) RouteSendAlertNotifications(c *contextmodel.ReqContext, sendNotificationsRequest apimodels.AlertSendNotificationsRequest) response.Response {
	c.Logger.Info("Sending alerts to local notifier", "count", len(sendNotificationsRequest.Alerts.PostableAlerts))
	n, err := srv.MultiOrgAlertmanager.AlertmanagerFor(sendNotificationsRequest.AlertRuleKey.OrgID)
	if err == nil {
		if err := n.PutAlerts(c.Req.Context(), sendNotificationsRequest.Alerts); err != nil {
			c.Logger.Error("Failed to put alerts in the local notifier", "count", len(sendNotificationsRequest.Alerts.PostableAlerts), "error", err)
		} else {
			return response.Success("Put alerts was successful")
		}
	} else {
		if errors.Is(err, notifier.ErrNoAlertmanagerForOrg) {
			c.Logger.Debug("Local notifier was not found")
		} else {
			c.Logger.Error("Local notifier is not available", "error", err)
		}
	}

	return response.Error(http.StatusInternalServerError, "Failed to put alerts", err)
}

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
