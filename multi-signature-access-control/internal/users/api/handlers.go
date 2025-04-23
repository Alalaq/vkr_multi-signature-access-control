package api

import (
	"github.com/labstack/echo/v4"
	"multi-signature-access-control/internal/users/dtos"
	"multi-signature-access-control/internal/users/usecase"
	"multi-signature-access-control/pkg/app_errors"
	"multi-signature-access-control/pkg/response"
)

type handler struct {
	uc usecase.Usecase
}

type Handlers interface {
	CreateUserHandler(c echo.Context) error
	LoginHandler(c echo.Context) error
	GetAllUsersHandler(c echo.Context) error
	GetNewRequestsHandler(c echo.Context) error
	SignRequestHandler(c echo.Context) error
	DeclineRequestHandler(c echo.Context) error
	GetPermissionRequestsHandler(c echo.Context) error
	RegisterHandler(c echo.Context) error
}

func NewUsersHandler(uc usecase.Usecase) Handlers {
	return &handler{uc: uc}
}

// @Summary		Create User
// @Description	Create User.
// @ID			create-user
// @Tags		Users
// @Accept		json
// @Produce		json
// @Param		body	body		dtos.CreateUserRequest	true	"User Object"
// @Success		200		{object}	response.ResponseFormat			"SUCCESS"
// @Failure		500		{object}	response.FailedResponse			"INTERNAL_SERVER__ERROR"
// @Router		/users [post]
// @Security	BearerToken
func (h *handler) CreateUserHandler(c echo.Context) error {
	var request dtos.CreateUserRequest
	if err := c.Bind(&request); err != nil {
		return response.ErrorBuilder(app_errors.BadRequest(err)).Send(c)
	}

	if err := c.Validate(request); err != nil {
		return response.ErrorBuilder(app_errors.BadRequest(err)).Send(c)
	}

	if err := h.uc.Create(c.Request().Context(), request); err != nil {
		return response.ErrorBuilder(err).Send(c)
	}

	return response.SuccessBuilder(nil).Send(c)
}

// @Summary		Register
// @Description Register
// @ID			Register
// @Tags		Users
// @Accept		json
// @Produce		json
// @Param		body	body		dtos.RegisterRequest		true				"Register Object"
// @Success		200  	{object}	response.Success{data=dtos.RegisterResponse}	"SUCCESS"
// @Failure		500		{object}	response.FailedResponse						"INTERNAL_SERVER__ERROR"
// @Router		/register [post]
func (h *handler) RegisterHandler(c echo.Context) error {
	var request dtos.RegisterRequest
	if err := c.Bind(&request); err != nil {
		return response.ErrorBuilder(app_errors.BadRequest(err)).Send(c)
	}

	if err := c.Validate(request); err != nil {
		return response.ErrorBuilder(app_errors.BadRequest(err)).Send(c)
	}

	loginData, err := h.uc.Register(c.Request().Context(), request)
	if err != nil {
		return response.ErrorBuilder(err).Send(c)
	}

	return response.SuccessBuilder(loginData).Send(c)
}

// @Summary		Login
// @Description Login
// @ID			login
// @Tags		Users
// @Accept		json
// @Produce		json
// @Param		body	body		dtos.LoginRequest		true				"Login Object"
// @Success		200  	{object}	response.Success{data=dtos.LoginResponse}	"SUCCESS"
// @Failure		500		{object}	response.FailedResponse						"INTERNAL_SERVER__ERROR"
// @Router		/login [post]
func (h *handler) LoginHandler(c echo.Context) error {
	var request dtos.LoginRequest
	if err := c.Bind(&request); err != nil {
		return response.ErrorBuilder(app_errors.BadRequest(err)).Send(c)
	}

	if err := c.Validate(request); err != nil {
		return response.ErrorBuilder(app_errors.BadRequest(err)).Send(c)
	}

	loginData, err := h.uc.Login(c.Request().Context(), request)
	if err != nil {
		return response.ErrorBuilder(err).Send(c)
	}

	return response.SuccessBuilder(loginData).Send(c)
}

// @Summary		GetAllUsers
// @Description GetAllUsers
// @ID			GetAllUsers
// @Tags		Users
// @Accept		json
// @Produce		json
// @Param		body	body		dtos.LoginRequest		true				"Login Object"
// @Success		200  	{object}	response.Success{data=dtos.LoginResponse}	"SUCCESS"
// @Failure		500		{object}	response.FailedResponse						"INTERNAL_SERVER__ERROR"
// @Router		/getall [post]
func (h *handler) GetAllUsersHandler(c echo.Context) error {
	loginData, err := h.uc.GetAllUsers(c.Request().Context())
	if err != nil {
		return response.ErrorBuilder(err).Send(c)
	}

	return response.SuccessBuilder(loginData).Send(c)
}

// @Summary		GetNewRequests
// @Description GetNewRequests
// @ID			GetNewRequests
// @Tags		PermissionRequests
// @Accept		json
// @Produce		json
// @Param		body	body		dtos.PermissionReqRequest		true				"Permission Requests Object"
// @Success		200  	{object}	response.Success{data=[]dtos.PermissionReqRequest}	"SUCCESS"
// @Failure		500		{object}	response.FailedResponse						"INTERNAL_SERVER__ERROR"
// @Router		/get_requests [post]
func (h *handler) GetNewRequestsHandler(c echo.Context) error {
	var request dtos.PermissionReqRequest
	if err := c.Bind(&request); err != nil {
		return response.ErrorBuilder(app_errors.BadRequest(err)).Send(c)
	}

	if err := c.Validate(request); err != nil {
		return response.ErrorBuilder(app_errors.BadRequest(err)).Send(c)
	}

	requests, err := h.uc.GetNewRequestsByUsername(c.Request().Context(), request.Username)
	if err != nil {
		return response.ErrorBuilder(err).Send(c)
	}

	return response.SuccessBuilder(requests).Send(c)
}

// @Summary	Sign Request
// @Description	Sign a permission request.
// @ID		sign-request
// @Tags	PermissionRequests
// @Accept	json
// @Produce	json
// @Param	body	body		dtos.SignRequest	true	"Sign Request Object"
// @Success	200	{object}	response.ResponseFormat	"SUCCESS"
// @Failure	500	{object}	response.FailedResponse	"INTERNAL_SERVER_ERROR"
// @Router	/sig_request [patch]
func (h *handler) SignRequestHandler(c echo.Context) error {
	var request dtos.PermissionReqRequest
	if err := c.Bind(&request); err != nil {
		return response.ErrorBuilder(app_errors.BadRequest(err)).Send(c)
	}

	if err := c.Validate(request); err != nil {
		return response.ErrorBuilder(app_errors.BadRequest(err)).Send(c)
	}

	if err := h.uc.SignRequest(c.Request().Context(), request); err != nil {
		return response.ErrorBuilder(err).Send(c)
	}

	return response.SuccessBuilder(nil).Send(c)
}

// @Summary	Decline Request
// @Description	Decline a permission request.
// @ID		decline-request
// @Tags	PermissionRequests
// @Accept	json
// @Produce	json
// @Param	body	body		dtos.DeclineRequest	true	"Decline Request Object"
// @Success	200	{object}	response.ResponseFormat	"SUCCESS"
// @Failure	500	{object}	response.FailedResponse	"INTERNAL_SERVER_ERROR"
// @Router	/decline_request [patch]
func (h *handler) DeclineRequestHandler(c echo.Context) error {
	var request dtos.PermissionReqRequest
	if err := c.Bind(&request); err != nil {
		return response.ErrorBuilder(app_errors.BadRequest(err)).Send(c)
	}

	if err := c.Validate(request); err != nil {
		return response.ErrorBuilder(app_errors.BadRequest(err)).Send(c)
	}

	if err := h.uc.DeclineRequest(c.Request().Context(), request); err != nil {
		return response.ErrorBuilder(err).Send(c)
	}

	return response.SuccessBuilder(nil).Send(c)
}

// @Summary	Get Permission Requests
// @Description	Get all permission requests.
// @ID		get-permission-requests
// @Tags	PermissionRequests
// @Accept	json
// @Produce	json
// @Success	200	{object}	response.Success{data=[]dtos.PermissionReqRequest}	"SUCCESS"
// @Failure	500	{object}	response.FailedResponse	"INTERNAL_SERVER_ERROR"
// @Router	/get_permission_requests [get]
func (h *handler) GetPermissionRequestsHandler(c echo.Context) error {
	var request dtos.PermissionReqRequest
	if err := c.Bind(&request); err != nil {
		return response.ErrorBuilder(app_errors.BadRequest(err)).Send(c)
	}

	if err := c.Validate(request); err != nil {
		return response.ErrorBuilder(app_errors.BadRequest(err)).Send(c)
	}

	requests, err := h.uc.GetPermissionRequests(c.Request().Context(), request.Username)
	if err != nil {
		return response.ErrorBuilder(err).Send(c)
	}

	return response.SuccessBuilder(requests).Send(c)
}
