package dtos

type PermissionReqRequest struct {
	Username   string `json:"username" validate:"required"`
	RequestID  string `json:"request_id"`
	PrivateKey string `json:"private_key"`
}
