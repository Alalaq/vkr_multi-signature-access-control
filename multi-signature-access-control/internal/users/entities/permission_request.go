package entities

import (
	"time"
)

type PermissionReq struct {
	ID          string    `json:"id" gorm:"type:string;primaryKey"`
	RequesterID string    `json:"requester_id" gorm:"type:string;not null"`
	RequesteeID string    `json:"requestee_id" gorm:"type:string;not null"`
	Resource    string    `json:"resource" gorm:"type:varchar(255);not null"`
	CreatedAt   time.Time `json:"created_at" gorm:"type:timestamp;default:current_timestamp"`
	IsAnswered  bool      `json:"is_answered" gorm:"type:boolean;default:false"`
	IsSigned    bool      `json:"is_signed" gorm:"type:boolean;default:false"`
}

type PermissionReqSignature struct {
	ID        string `gorm:"column:id"`
	Username  string `gorm:"column:username"`
	Signature []byte `gorm:"column:signature"`
}
type RecentPermissionReqResponse struct {
	ID         string    `json:"id" gorm:"type:string;primaryKey"`
	Resource   string    `json:"resource" gorm:"type:varchar(255);not null"`
	CreatedAt  time.Time `json:"created_at" gorm:"type:timestamp;default:current_timestamp"`
	IsAnswered bool      `json:"is_answered" gorm:"type:boolean;default:false"`
	IsSigned   bool      `json:"is_signed" gorm:"type:boolean;default:false"`
}

type PermissionReqResponse struct {
	Resource       string    `json:"resource" gorm:"type:varchar(255);not null"`
	ApprovesNeeded int       `json:"approves_needed" gorm:"type:integer;not null"`
	ApprovesGiven  int       `json:"approves_given" gorm:"type:integer;not null"`
	Answered       int       `json:"answered" gorm:"type:integer;not null"`
	CreatedAt      time.Time `json:"created_at" gorm:"type:timestamp;default:current_timestamp"`
}

func MapPermReqToResponse(permReq PermissionReq) RecentPermissionReqResponse {
	return RecentPermissionReqResponse{
		ID:         permReq.ID,
		Resource:   permReq.Resource,
		CreatedAt:  permReq.CreatedAt,
		IsAnswered: permReq.IsAnswered,
		IsSigned:   permReq.IsSigned,
	}
}

func MapPermReqsToResponse(permReqs []PermissionReq) []RecentPermissionReqResponse {
	var res []RecentPermissionReqResponse
	for _, permReq := range permReqs {
		res = append(res, MapPermReqToResponse(permReq))
	}
	return res
}
