package constants

// todo maybe get rid of it and make structure with fields role and id
type JWTPermission string

type UserRole string

const (
	AdminUserRole    UserRole = "ADMIN"
	EmployeeUserRole UserRole = "EMPLOYEE"
	ManagerUserRole  UserRole = "MANAGER"
)

type UserRoleID string

const (
	Manager  UserRoleID = "8ec8bb2c-d50a-4d9b-9534-dc3be0e11b4f"
	Employee UserRoleID = "a123bfe6-d39f-42b2-b1e2-c7f7f4fc184d"
	Admin    UserRoleID = "f0bce51b-8c3d-4f76-bf1d-38308c4699a7"
)

func (ur UserRoleID) String() string {
	return string(ur)
}

var RoleIDs = []UserRoleID{
	Admin,
	Employee,
	Manager,
}

type ResponseMessage string

const (
	InternalServerError ResponseMessage = "internal_server_error"
	BadRequest          ResponseMessage = "bad_request"
	Success             ResponseMessage = "success"
	Unauthorized        ResponseMessage = "unauthorized"
	Forbidden           ResponseMessage = "forbidden"
	NotFound            ResponseMessage = "not_found"
	Conflict            ResponseMessage = "conflict"
	GatewayTimeOut      ResponseMessage = "gateway_timeout"
)

type AccessLevel string

const (
	NoAccess        AccessLevel = "no_access"
	LowAccessLevel  AccessLevel = "low_access"
	HighAccessLevel AccessLevel = "high_access"
)

func (rm ResponseMessage) String() string {
	return string(rm)
}

type HeaderKey string

const (
	AuthorizationHeaderKey HeaderKey = "Authorization"
	SignatureHeaderKey     HeaderKey = "PrivateKey"
	UsernameHeaderKey      HeaderKey = "Username"
)

func (hk HeaderKey) String() string {
	return string(hk)
}

type ContextKey string

const (
	AuthCredentialContextKey ContextKey = "auth_credential"
)

func (ck ContextKey) String() string {
	return string(ck)
}

const (
	BlacklistedToken = "blacklisted"
)

type XRequestID string

var XRequestIDKey XRequestID = "X-Request-ID"

func (x XRequestID) String() string {
	return string(x)
}
