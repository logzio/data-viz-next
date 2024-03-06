package api

// LOGZ.IO GRAFANA CHANGE :: 43744, DEV-43895: add endpoints to evaluate and process alerts
import (
	"fmt"
	"github.com/grafana/grafana/pkg/services/ngalert/schedule"
	"net/http"

	"github.com/grafana/grafana/pkg/api/response"
	"github.com/grafana/grafana/pkg/infra/log"
	contextmodel "github.com/grafana/grafana/pkg/services/contexthandler/model"
	apimodels "github.com/grafana/grafana/pkg/services/ngalert/api/tooling/definitions"
	"github.com/grafana/grafana/pkg/services/ngalert/eval"

	"github.com/grafana/grafana/pkg/setting"
)

type LogzioAlertingService struct {
	Cfg              *setting.Cfg
	EvaluatorFactory eval.EvaluatorFactory
	Log              log.Logger
	Schedule         schedule.ScheduleService
}

func NewLogzioAlertingService(
	Cfg *setting.Cfg,
	EvaluatorFactory eval.EvaluatorFactory,
	log log.Logger,
	Schedule schedule.ScheduleService,
) *LogzioAlertingService {
	return &LogzioAlertingService{
		Cfg:              Cfg,
		EvaluatorFactory: EvaluatorFactory,
		Log:              log,
		Schedule:         Schedule,
	}
}

func (srv *LogzioAlertingService) RouteEvaluateAlert(c *contextmodel.ReqContext, evalRequests []apimodels.AlertEvaluationRequest) response.Response {
	c.Logger.Info(fmt.Sprintf("Evaluate Alert API: got requests for %d evaluations", len(evalRequests)))
	var evaluationsErrors []apimodels.AlertEvalRunResult

	for _, evalRequest := range evalRequests {
		c.Logger.Info("Evaluate Alert API", "evalTime", evalRequest.EvalTime, "ruleTitle", evalRequest.AlertRule.Title, "ruleUID", evalRequest.AlertRule.UID)
		err := srv.Schedule.RunRuleEvaluation(c.Req.Context(), evalRequest)

		if err != nil {
			evaluationsErrors = append(evaluationsErrors, apimodels.AlertEvalRunResult{UID: evalRequest.AlertRule.UID, EvalTime: evalRequest.EvalTime, RunResult: err.Error()})
		} else {
			evaluationsErrors = append(evaluationsErrors, apimodels.AlertEvalRunResult{UID: evalRequest.AlertRule.UID, EvalTime: evalRequest.EvalTime, RunResult: "success"})
		}
	}

	c.Logger.Info("Evaluate Alert API - Done", "evalErrors", evaluationsErrors)
	return response.JSON(http.StatusOK, apimodels.EvalRunsResponse{RunResults: evaluationsErrors})
}
