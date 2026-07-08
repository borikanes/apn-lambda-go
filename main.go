package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/gbrlsnchs/jwt/v3"
)

func init() {
	log.Printf("Lambda loaded into memory")
	if err := ensureFreshToken(); err != nil {
		fmt.Printf("Error generating request initially => %s", err.Error())
	}
}

var jwtToken = ""

// jwtIssuedAt tracks when jwtToken was generated. Apple rejects provider tokens older
// than 1 hour (ExpiredProviderToken), and warm lambda containers can live much longer
// than that, so the token must be refreshed based on age rather than only at init.
var jwtIssuedAt time.Time

// tokenMaxAge is how old a provider token may get before we proactively regenerate it.
// Kept under Apple's 1 hour limit, but comfortably over their 20 minute minimum between
// token updates (refreshing too often triggers TooManyProviderTokenUpdates).
const tokenMaxAge = 50 * time.Minute

// curl command to make request to APN
// curl -v -d '{"aps":{"alert":"hello"}}' -H "apns-topic: <bundle_id>" -H "authorization: bearer " --http2 https://api.development.push.apple.com/3/device/<device_token>

const (
	sandboxBaseURL    = "https://api.development.push.apple.com/"
	productionBaseURL = "https://api.push.apple.com/"
)

// EventPayload represents the structure of the json response
type EventPayload struct {
	Message     string `json:"message"`
	DeviceToken string `json:"deviceToken"`
	BundleID    string `json:"bundleID"`
}

// APSPayload is the Top level aps json object
type APSPayload struct {
	Aps APSBodyPayload `json:"aps"`
}

// APSBodyPayload is the nested json in aps json
type APSBodyPayload struct {
	Alert string `json:"alert"`
	Sound string `json:"sound"`
}

// LambdaResponse represents the response from the lambda
type LambdaResponse struct {
	Base64Encoded bool              `json:"isBase64Encoded"`
	Headers       map[string]string `json:"headers"`
	Message       string            `json:"message"`
	StatusCode    int               `json:"statusCode"`
}

// HandleLambdaEvent receives a notification event, builds the APNs request and sends it.
// It returns a 200 LambdaResponse on success, or an error describing the APNs rejection
// (including Apple's {"reason":...} body) on failure.
func HandleLambdaEvent(event EventPayload) (LambdaResponse, error) {
	log.Printf("Message: %s || Device Token: %s || BundleID: %s", event.Message, event.DeviceToken, event.BundleID)

	// Regenerate the provider token if the warm container has held it close to Apple's 1 hour limit
	if err := ensureFreshToken(); err != nil {
		log.Printf("Error refreshing provider token => %s", err.Error())
		return LambdaResponse{}, errors.New("Error generating provider token. 500 Error")
	}

	apsBodyPayload := APSBodyPayload{Alert: event.Message, Sound: "default"}
	apnRequest, err := formRequestObject(APSPayload{Aps: apsBodyPayload}, event.DeviceToken, event.BundleID)
	if err != nil {
		log.Printf("Error forming request object, see below for more info")
		return LambdaResponse{}, errors.New("Error forming request object. 500 Error")
	}

	// Send request
	statusCode, apnsBody, sendRequestErr := sendRequest(apnRequest)

	// Token rejected; refresh and resend request
	if statusCode == http.StatusForbidden {
		log.Printf("Got a 403.....Refreshing token now.")
		var generateTokenError error // Need error object because generateJWTToken returns error
		jwtToken, generateTokenError = generateJWTToken(os.Getenv("PRIVATE_KEY_FILE_NAME")) // Reassign refreshed token to global jwtToken variable
		// Issue with token generation
		if generateTokenError != nil {
			log.Printf("Error in generating token when request to APN is 403. Error => %s", generateTokenError.Error())
			return LambdaResponse{}, errors.New("Error generating token when trying to refresh. 500 Error")
		}
		jwtIssuedAt = time.Now()
		// The first send consumed the request body, so the request must be rebuilt —
		// resending the same *http.Request causes an HTTP/2 PROTOCOL_ERROR
		apnRequest, err = formRequestObject(APSPayload{Aps: apsBodyPayload}, event.DeviceToken, event.BundleID)
		if err != nil {
			return LambdaResponse{}, errors.New("Error forming request object for retry. 500 Error")
		}
		// Resend request and reassign statusCode and err.
		statusCode, apnsBody, sendRequestErr = sendRequest(apnRequest)
	}
	// If statusCode is not 200 just return error to client.
	if statusCode != http.StatusOK {
		log.Printf("Notification request returned a non 200 statusCode")
		if sendRequestErr != nil {
			log.Printf("Error Deets %s", sendRequestErr)
		}
		switch statusCode {
		case http.StatusBadRequest:
			return LambdaResponse{}, fmt.Errorf("Something is wrong with the request sent. %d Error. APNs said: %s", statusCode, apnsBody)
		case http.StatusForbidden:
			return LambdaResponse{}, fmt.Errorf("Provider token rejected and the refresh did not help. %d Error. APNs said: %s", statusCode, apnsBody)
		case http.StatusNotFound:
			return LambdaResponse{}, fmt.Errorf("Path not found, maybe the device token is invalid or you broke something sucker. %d Error. APNs said: %s", statusCode, apnsBody)
		default:
			return LambdaResponse{}, fmt.Errorf("Request wasnt successful. %d Error. APNs said: %s", statusCode, apnsBody)
		}
	}

	// if response is a 200
	return LambdaResponse{Message: "Notification sent successfully", StatusCode: 200, Base64Encoded: false, Headers: map[string]string{}}, nil
}

// ensureFreshToken regenerates the global jwtToken when it is missing or older than
// tokenMaxAge. Returns an error if token generation fails; on success jwtToken and
// jwtIssuedAt are updated.
func ensureFreshToken() error {
	if jwtToken != "" && time.Since(jwtIssuedAt) < tokenMaxAge {
		return nil
	}
	token, err := generateJWTToken(os.Getenv("PRIVATE_KEY_FILE_NAME"))
	if err != nil {
		return err
	}
	jwtToken = token
	jwtIssuedAt = time.Now()
	return nil
}

// generateJWTToken reads the .p8 private key at privateKeyPath and signs an ES256 APNs
// provider token with TEAM_ID as issuer and KEY_ID as key id. Returns the signed JWT.
func generateJWTToken(privateKeyPath string) (string, error) {
	keyBytes, err := os.ReadFile(privateKeyPath)
	if err != nil {
		log.Printf("Error reading private key file. Error => %s", err.Error())
		return "", err
	}

	block, _ := pem.Decode(keyBytes)
	if block == nil {
		fmt.Printf("block is nil")
	} else if block.Type != "PRIVATE KEY" {
		fmt.Printf("Block is not PRIVATE_KEY")
	}

	privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		log.Printf("Error when parsing private key. Error => %s", err.Error())
		return "", err
	}

	actualPrivateKey, status := privateKey.(*ecdsa.PrivateKey)
	if !status {
		log.Printf("Status is not false when pulling the privateKey field from the parser struct")
	}

	var alg = jwt.NewES256(jwt.ECDSAPrivateKey(actualPrivateKey))
	var now = time.Now()
	var jwtPayload = jwt.Payload{
		Issuer:   os.Getenv("TEAM_ID"),
		IssuedAt: jwt.NumericDate(now),
	}

	token, error := jwt.Sign(jwtPayload, alg, jwt.KeyID(os.Getenv("KEY_ID")))
	if error != nil {
		log.Printf("Error when trying to jwt Sign. Error => %s", error.Error())
		return "", error
	}

	return string(token), nil
}

// formRequestObject builds the APNs HTTP request for the given payload, device token and
// bundle id. QA bundle ids are routed to the APNs sandbox. The returned request is
// single-use: its body is consumed on send, so build a new one per attempt.
func formRequestObject(payload APSPayload, deviceToken string, bundleID string) (*http.Request, error) {
	// convert to json
	requestBody, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	// get endpoint based on environment
	baseEndpoint := productionBaseURL
	if bundleID == "me.borikanes.SongUpdaterQA" {
		baseEndpoint = sandboxBaseURL
	}

	// create request object
	fullURL := baseEndpoint + "3/device/" + deviceToken
	request, err := http.NewRequest("POST", fullURL, bytes.NewBuffer(requestBody))
	if err != nil {
		return nil, err
	}

	// set headers
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("apns-topic", bundleID)
	request.Header.Set("apns-push-type", "alert")

	return request, nil
}

// 403 - {"reason":"ExpiredProviderToken"}
// 403 - {"reason":"InvalidProviderToken"}
// 404 - {"reason":"BadDeviceToken"}
// 404 - {"reason":"BadPath"}

// sendRequest attaches the provider token and sends the request to APNs. Returns the
// response status code and body (Apple puts the rejection {"reason":...} there), or a
// 500 with the transport error if the request could not be sent at all.
func sendRequest(request *http.Request) (int, string, error) {
	request.Header.Set("authorization", "Bearer "+jwtToken)
	// Deliberately not logging headers here — the authorization header carries the JWT
	log.Printf("Sending %s %s to APN", request.Method, request.URL)
	client := &http.Client{}
	response, err := client.Do(request)
	if err != nil {
		return 500, "", err
	}
	defer response.Body.Close()

	bodyBytes, readErr := io.ReadAll(response.Body)
	if readErr != nil {
		log.Printf("Could not read APN response body. Error => %s", readErr.Error())
	}
	responseBody := string(bodyBytes)
	log.Printf("APN response => Status Code: %d Body: %s", response.StatusCode, responseBody)
	return response.StatusCode, responseBody, nil
}

func main() {
	// Local development
	// lambdaResponse, error := HandleLambdaEvent(EventPayload{Message: "MESSAGE!!!", DeviceToken: "123456789", BundleID: "com.apple.develop"})
	// if error != nil {
	//     fmt.Println(error)
	// }
	// fmt.Println(lambdaResponse)
	lambda.Start(HandleLambdaEvent)
}
