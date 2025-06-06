package echo

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/invopop/validation"
	"github.com/labstack/echo/v4"
	"github.com/valyala/fasthttp"
	"multi-signature-access-control/pkg/app_errors"
	"multi-signature-access-control/pkg/response"
)

// errorHandler handles HTTP errors and sends a custom response based on the error type.
// Parameters:
//   - err: The error that occurred.
//   - c: The Echo context.
func errorHandler(err error, c echo.Context) {
	// Unauthorized Error
	var jwtErr *jwt.ValidationError
	if errors.As(err, &jwtErr) || errors.Is(err, app_errors.ErrMissingOrMalformatJWT) {
		response.ErrorBuilder(app_errors.Unauthorized(err)).Send(c)

		return
	}

	var echoErr *echo.HTTPError
	if errors.As(err, &echoErr) {
		switch echoErr.Code {
		case http.StatusNotFound:
			response.ErrorBuilder(app_errors.NotFound(app_errors.ErrRouteNotFound)).Send(c)

			return
		default:
			response.ErrorBuilder(err).Send(c)

			return
		}
	}

	// Path Parse Error
	var numErr *strconv.NumError
	if errors.As(err, &numErr) {
		response.ErrorBuilder(app_errors.BadRequest(app_errors.ErrMalformatBody)).Send(c)

		return
	}

	// handle HTTP Error
	var appErr *app_errors.AppError
	if errors.As(err, &appErr) {
		response.ErrorBuilder(err).Send(c)

		return
	}

	var validatorError validation.Errors
	if errors.As(err, &validatorError) {
		response.ErrorBuilder(app_errors.BadRequest(app_errors.ErrValidation)).Send(c)
		return
	}

	// JSON Format Error
	var jsonSyntaxErr *json.SyntaxError
	if errors.As(err, &jsonSyntaxErr) {
		response.ErrorBuilder(app_errors.BadRequest(app_errors.ErrMalformatBody)).Send(c)

		return
	}

	// Unmarshal Error
	var unmarshalErr *json.UnmarshalTypeError
	if errors.As(err, &unmarshalErr) {
		var translatedType string
		switch unmarshalErr.Type.Name() {
		// REGEX *int*
		case "int8", "int16", "int32", "int64", "uint8", "uint16", "uint32", "uint64", "float32", "float64":
			translatedType = "number"
		case "Time":
			translatedType = "date time"
		case "string":
			translatedType = "string"
		}

		response.ErrorBuilder(app_errors.BadRequest(fmt.Errorf("the field must be a valid %s", translatedType))).Send(c)
		return
	}

	//time parse error
	var timeParseErr *time.ParseError
	if errors.As(err, &timeParseErr) {
		v := timeParseErr.Value
		if v == "" {
			v = "empty string (``)"
		}

		response.ErrorBuilder(app_errors.BadRequest(fmt.Errorf("invalid time format on %s", v))).Send(c)

		return
	}

	// Multipart Error
	if errors.Is(err, fasthttp.ErrNoMultipartForm) {
		response.ErrorBuilder(app_errors.BadRequest(app_errors.ErrInvalidMultiPart)).Send(c)

		return
	}

	//TCP connection error
	var tcpErr *net.OpError
	if errors.As(err, &tcpErr) {
		log.Fatalf("unable to get tcp connection from %s, shutting down...", tcpErr.Addr.String())
	}

	response.ErrorBuilder(err).Send(c)
}
