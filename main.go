package main

import (
        "bytes"
        "crypto/ecdsa"
        "crypto/x509"
        "encoding/json"
        "encoding/pem"
        "errors"
        "fmt"
        "github.com/aws/aws-lambda-go/lambda"
        "github.com/gbrlsnchs/jwt"
        "io/ioutil"
        "log"
        "net/http"
        "os"
        "time"

)

func init() {
    log.Printf("Lambda loaded into memory")
    var err error
    jwtToken, err = generateJWTToken(os.Getenv("PRIVATE_KEY_FILE_NAME"))
    if err != nil {
        fmt.Printf("Error generating request initially => %s", err.Error())
    }
}

var jwtToken = ""
// curl command to make request to APN
// curl -v -d '{"aps":{"alert":"hello"}}' -H "apns-topic: <bundle_id>" -H "authorization: bearer " --http2 https://api.development.push.apple.com/3/device/<device_token>

const (
    sandboxBaseURL = "https://api.development.push.apple.com/"
    productionBaseURL = "https://api.push.apple.com/"
)

// EventPayload represents the structure of the json response
type EventPayload struct {
        Message string         `json:"message"`
        DeviceToken string     `json:"deviceToken"`
        BundleID string        `json:"bundleID"`
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
    Base64Encoded bool `json:"isBase64Encoded"`
    Headers map[string]string `json:"headers"`
    Message string `json:"message"`
    StatusCode int `json:"statusCode"`
}

// HandleLambdaEvent is the lambda event lambda
func HandleLambdaEvent(event EventPayload) (LambdaResponse, error) {
    log.Printf("Message: %s || Device Token: %s || BundleID: %s", event.Message, event.DeviceToken, event.BundleID)

    apsBodyPayload := APSBodyPayload{Alert: event.Message, Sound: "default"}
    apnRequest, err := formRequestObject(APSPayload {Aps: apsBodyPayload}, event.DeviceToken, event.BundleID)
    if err != nil {
        log.Printf("Error forming request object, see below for more info")
        return LambdaResponse{}, errors.New("Error forming request object. 500 Error")
    }

    // Send request
    statusCode, sendRequestErr := sendRequest(apnRequest)

    // Token expired, refresh and resend request
    if statusCode == http.StatusForbidden {
        log.Printf("Got a 403.....Refreshing token now.")
        var generateTokenError error // Need error object because generateJWTToken returns error
        jwtToken, generateTokenError = generateJWTToken(os.Getenv("PRIVATE_KEY_FILE_NAME")) // Reassign refreshed token to global jwtToken variable
        // Issue with token generation
        if generateTokenError != nil {
            log.Printf("Error in generating token when request to APN is 403. Error => %s", generateTokenError.Error())
            return LambdaResponse{}, errors.New("Error generating token when trying to refresh. 500 Error")
        }
        // Resend request and reassign statusCode and err.
        statusCode, sendRequestErr = sendRequest(apnRequest)
    }
    // If statusCode is not 200 just return error to client.
    if statusCode != http.StatusOK {
        log.Printf("Notification request returned a non 200 statusCode")
        log.Printf("Error Deets %s", sendRequestErr)
        switch statusCode {
        case http.StatusBadRequest:
            return LambdaResponse{}, fmt.Errorf("Something is wrong with the request sent. %d Error", statusCode)
        case http.StatusForbidden:
            return LambdaResponse{}, fmt.Errorf("Token must have expired and the refresh did not work. %d Error", statusCode)
        case http.StatusNotFound:
            return LambdaResponse{}, fmt.Errorf("Path not found, maybe the device token is invalid or you broke something sucker. %d Error", statusCode)
        default:
            return LambdaResponse{}, fmt.Errorf("Request wasnt successful. %d Error", statusCode)
        }
    }

    // if response is a 200
    return LambdaResponse{Message: "Notification sent successfully", StatusCode: 200, Base64Encoded: false, Headers: map[string]string{}}, nil
}

func generateJWTToken(privateKeyPath string) (string, error) {
    // bytes, err := ioutil.ReadFile(os.Getenv("PRIVATE_KEY_FILE_NAME"))
    bytes, err := ioutil.ReadFile(privateKeyPath)
    if err != nil {
        log.Printf("Error reading private key file. Error => %s", err.Error())
        // fmt.Printf("Error reading file")
        return "", err
    }

    block, _ := pem.Decode(bytes)
    if block == nil {
    	fmt.Printf("block is nil")
    } else if block.Type != "PRIVATE KEY" {
    	fmt.Printf("Block is not PRIVATE_KEY")
    }

    privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
    if err != nil {
    log.Printf("Error when parsing private key. Error => %s", err.Error())
    // fmt.Printf("There was an error %s", err)
    return "", err
    }

    actualPrivateKey, status := privateKey.(*ecdsa.PrivateKey)
    if !status {
        log.Printf("Status is not false when pulling the privateKey field from the parser struct")
    }

    var alg = jwt.NewES256(jwt.ECDSAPrivateKey(actualPrivateKey))
    var now = time.Now()
    var jwtPayload = jwt.Payload {
        Issuer: os.Getenv("TEAM_ID"),
        IssuedAt: jwt.NumericDate(now),
    }

    token, error := jwt.Sign(jwtPayload, alg, jwt.KeyID(os.Getenv("KEY_ID")))
    if error != nil {
      log.Printf("Error when trying to jwt Sign. Error => %s", error.Error())
      return "",error
    }
    fmt.Println(string(token))

    return string(token),nil
}

func formRequestObject(payload APSPayload, deviceToken string, bundleID string) (*http.Request, error) {
    // convert to json
    requestBody, err := json.Marshal(payload)
    if err != nil {
        return nil,err
    }

    // get endpoint based on environment
    baseEndpoint := productionBaseURL
    if bundleID == "me.borikanes.SongUpdaterQA" {
        baseEndpoint = sandboxBaseURL
    }
    // baseEndpoint := sandboxBaseURL

    // create request object
    fullURL := baseEndpoint + "3/device/" + deviceToken
    request, err := http.NewRequest("POST", fullURL, bytes.NewBuffer(requestBody))
    if err != nil {
        return nil, err
    }

    // set headers
    request.Header.Set("Content-Type", "application/json")
    request.Header.Set("apns-topic", bundleID)
    // request.Header.Set("authorization", "Bearer "+jwtToken)

    return request, nil
}

// 403 - {"reason":"ExpiredProviderToken"}
// 403 - {"reason":"InvalidProviderToken"}
// 404 - {"reason":"BadDeviceToken"}
// 404 - {"reason":"BadPath"}
func sendRequest(request *http.Request) (int, error) {
    request.Header.Set("authorization", "Bearer "+jwtToken)
    log.Printf("Request sent to APN %+v", request)
    client := &http.Client {}
    response, err := client.Do(request)
    if err != nil {
        return 500, err
    }
    // print response body
    // bodyBytes, _ := ioutil.ReadAll(response.Body)
    // log.Println(string(bodyBytes))
    defer response.Body.Close()

    log.Printf("Status Code when sending request => Status Code: %d", response.StatusCode)
    return response.StatusCode, nil
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
