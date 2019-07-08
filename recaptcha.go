package recaptcha

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"
)

type Recaptcha struct {
	Url    string `json:"url"`
	Server string `json:"-"`
	Client string `json:"client"`
	Action string `json:"action"`
	Field  string `json:"field"`
}

type Response struct {
	Success     bool      `json:"success"`
	Score       int       `json:"score"`
	Action      string    `json:"action"`
	ChallengeTs time.Time `json:"challenge_ts"`
	HostName    string    `json:"hostname"`
	ErrorCodes  string    `json:"error_codes"`
}

func (r *Recaptcha) Verify(code string, ip string) (*Response, error) {
	param := url.Values{
		"secret":   []string{r.Server},
		"response": []string{code},
		"remoteip": []string{ip},
	}
	req, err := http.NewRequest("POST", fmt.Sprintf("%s/recaptcha/api/siteverify", r.Url), bytes.NewBufferString(param.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	buffer, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	result := &Response{}
	err = json.Unmarshal(buffer, result)
	if err != nil {
		return nil, err
	}
	if !result.Success {
		return result, errors.New(result.ErrorCodes)
	}
	return result, nil
}

func (r *Recaptcha) VerifyRequest(req *http.Request) (*Response, error) {
	return r.Verify(req.FormValue(r.Field), req.RemoteAddr)
}

func (r *Recaptcha) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]string{
		"url":    r.Url,
		"client": r.Client,
		"action": r.Action,
	})
}

func New(server string, client string) *Recaptcha {
	return &Recaptcha{
		Url:    "https://www.recaptcha.net", //or https://www.google.com
		Server: server,
		Client: client,
		Field:  "captcha",
		Action: "social", // homepage/login/social/e-commerce see: https://developers.google.com/recaptcha/docs/v3#score
	}
}
