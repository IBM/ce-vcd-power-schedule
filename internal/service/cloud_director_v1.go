// cloud_director_v1.go
package clouddirector

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"reflect"
	"runtime"
	"strings"
	"time"

	"github.com/IBM/go-sdk-core/v5/core"
	cleanhttp "github.com/hashicorp/go-cleanhttp"
)

// CloudDirectorV1 client
type CloudDirectorV1 struct {
	ServiceURL     string
	Auth           *BearerTokenAuth
	DefaultHeaders http.Header
	Client         *http.Client
	UserAgent      string
	Log            *slog.Logger
	Timeout        time.Duration
}

// CloudDirectorV1Options : Service options
type CloudDirectorV1Options struct {
	URL      string
	Org      string
	IAMToken string
	Auth     BearerTokenAuth
	Log      *slog.Logger
	Timeout  time.Duration
}

const (
	APIVersion          = "39.1"
	headerNameUserAgent = "User-Agent"
	sdkName             = "cloud-director-go-sdk"
	Version             = "0.0.1"
)

// NewCloudDirectorV1 creates a new CloudDirectorV1 service instance.
func NewCloudDirectorV1(options *CloudDirectorV1Options) (service *CloudDirectorV1, err error) {
	bearerTokenAuthOptions := BearerTokenAuthOptions{
		BaseURL:  options.URL,
		Org:      options.Org,
		Version:  APIVersion,
		IAMToken: options.IAMToken,
		Log:      *options.Log,
	}
	auth, err := NewBearerTokenAuth(&bearerTokenAuthOptions)
	if err != nil {
		return nil, err
	}

	service = &CloudDirectorV1{
		ServiceURL: options.URL,
		Auth:       auth,
		Client:     DefaultHTTPClient(),
		Log:        options.Log.With("service", sdkName),
	}

	service.SetUserAgent(service.buildUserAgent())
	service.SetTimeout(options.Timeout)

	return service, nil
}

// DefaultHTTPClient returns a new HTTP client with minimum TLS version set.
// This function uses go-cleanhttp's pooled client for efficiency.
func DefaultHTTPClient() *http.Client {
	client := cleanhttp.DefaultPooledClient()
	setMinimumTLSVersion(client)
	return client
}

// setMinimumTLSVersion configures the provided HTTP client to use a minimum TLS version.
// This function is a helper to ensure secure communication by setting the minimum TLS version.
func setMinimumTLSVersion(client *http.Client) {
	if tr, ok := client.Transport.(*http.Transport); tr != nil && ok {
		if tr.TLSClientConfig == nil {
			tr.TLSClientConfig = &tls.Config{} // #nosec G402
		}

		tr.TLSClientConfig.MinVersion = tls.VersionTLS12
	}
}

func (service *CloudDirectorV1) GetHTTPClient() *http.Client {
	return service.Client
}

func (service *CloudDirectorV1) SetHTTPClient(client *http.Client) {
	setMinimumTLSVersion(client)
	service.Client = client
}

func (service *CloudDirectorV1) DisableSSLVerification() {
	// Make sure we have a non-nil client hanging off the BaseService.
	if service.Client == nil {
		service.Client = DefaultHTTPClient()
	}

	client := service.GetHTTPClient()
	if tr, ok := client.Transport.(*http.Transport); tr != nil && ok {
		// If no TLS config, then create a new one.
		if tr.TLSClientConfig == nil {
			tr.TLSClientConfig = &tls.Config{} // #nosec G402
		}

		// Disable server ssl cert & hostname verification.
		tr.TLSClientConfig.InsecureSkipVerify = true // #nosec G402
	}
	service.Log.Debug("Disabled SSL verification in HTTP client")
}

var systemInfo = fmt.Sprintf("(lang=go; arch=%s; os=%s; go.version=%s)", runtime.GOARCH, runtime.GOOS, runtime.Version())

func GetSystemInfo() string {
	return systemInfo
}

// buildUserAgent builds the user agent string.
func (service *CloudDirectorV1) buildUserAgent() string {
	return fmt.Sprintf("%s-%s %s", sdkName, Version, GetSystemInfo())
}

// SetUserAgent sets the user agent value.
func (service *CloudDirectorV1) SetUserAgent(userAgent string) {
	if userAgent == "" {
		userAgent = service.buildUserAgent()
	}
	service.UserAgent = userAgent
	service.Log.Debug("Set User-Agent", slog.String("userAgent", userAgent))
}

// SetUserAgent sets timeout value.
func (service *CloudDirectorV1) SetTimeout(timeout time.Duration) {
	if timeout <= 0 {
		timeout = 15 * time.Minute
	}
	service.Timeout = timeout
	service.Log.Debug("Set Timeout", slog.String("timeout", timeout.String()))
}

// SetServiceURL imposta l'URL base del servizio.
func (service *CloudDirectorV1) SetServiceURL(serviceURL string) error {
	if err := validateURL(serviceURL); err != nil {
		return err
	}
	service.ServiceURL = strings.TrimRight(serviceURL, "/")
	service.Log.Info("Service URL set", slog.String("url", service.ServiceURL))
	return nil
}

// One record element for query collections.
type Record struct {
	Href        *string `json:"href"`
	ID          *string `json:"id"`   // nullable
	Type        *string `json:"type"` // nullable
	Name        *string `json:"name"`
	Description *string `json:"description"` // nullable
	Version     *string `json:"version"`
	Status      *string `json:"status"` // nullable
}

// ListObjectsCollection : Query collection response.
type ObjectCollection struct {
	Href     *string  `json:"href"`
	Type     *string  `json:"type"`
	Name     *string  `json:"name"`
	Page     int      `json:"page"`
	PageSize int      `json:"pageSize"`
	Total    int      `json:"total"`
	Records  []Record `json:"record" validate:"required"`
}

// UnmarshalRecord unmarshals an instance of Record from the specified map of raw messages.
func UnmarshalRecord(m map[string]json.RawMessage, result interface{}) (err error) {
	obj := new(Record)
	err = core.UnmarshalPrimitive(m, "href", &obj.Href)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "id", &obj.ID)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "type", &obj.Type)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "name", &obj.Name)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "description", &obj.Description)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "version", &obj.Version)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "status", &obj.Status)
	if err != nil {
		return
	}
	reflect.ValueOf(result).Elem().Set(reflect.ValueOf(obj))
	return
}

func UnmarshalObjectCollection(m map[string]json.RawMessage, result interface{}) (err error) {
	obj := new(ObjectCollection)
	err = core.UnmarshalPrimitive(m, "href", &obj.Href)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "type", &obj.Type)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "name", &obj.Name)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "page", &obj.Page)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "pageSize", &obj.PageSize)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "total", &obj.Total)
	if err != nil {
		return
	}
	err = core.UnmarshalModel(m, "record", &obj.Records, UnmarshalRecord)
	if err != nil {
		return
	}
	reflect.ValueOf(result).Elem().Set(reflect.ValueOf(obj))
	return
}

type ListObjectsOptions struct {
	Filter   Filter
	Type     string
	sortAsc  *string
	sortDesc *string
}

func (service *CloudDirectorV1) listObjects(listObjectsOptions *ListObjectsOptions) (result *ObjectCollection, response *core.DetailedResponse, err error) {
	builder := core.NewRequestBuilder(core.GET)
	_, err = builder.ResolveRequestURL(service.ServiceURL, `/api/query`, nil)
	if err != nil {
		return
	}
	if listObjectsOptions.Type != "" {
		builder.AddQuery("type", listObjectsOptions.Type)
	}
	if listObjectsOptions.Filter != nil {
		filtered, err := ToFilterString(listObjectsOptions.Filter)
		if err != nil {
			return nil, nil, err
		}
		builder.AddQuery("filter", filtered)
	}
	if listObjectsOptions.sortAsc != nil {
		builder.AddQuery("sortAsc", fmt.Sprint(*listObjectsOptions.sortAsc))
	}
	if listObjectsOptions.sortDesc != nil {
		builder.AddQuery("sortDesc", fmt.Sprint(*listObjectsOptions.sortDesc))
	}
	builder.AddHeader("Accept", "application/*+json;version="+APIVersion)
	request, err := builder.Build()
	if err != nil {
		return
	}
	var rawResponse map[string]json.RawMessage
	response, err = service.Request(request, &rawResponse)
	if err != nil {
		return
	}
	if rawResponse != nil {
		err = core.UnmarshalModel(rawResponse, "", &result, UnmarshalObjectCollection)
		if err != nil {
			return
		}
		response.Result = result
	}
	return
}

type GetObjectByNameOptions struct {
	Name string
	Type string
}

func (service *CloudDirectorV1) GetObjectByName(getObjectsByNameOptions *GetObjectByNameOptions) (result *Record, response *core.DetailedResponse, err error) {
	listObjectsOptions := &ListObjectsOptions{
		Filter: Condition{Field: "name", Operator: Eq, Value: getObjectsByNameOptions.Name},
		Type:   getObjectsByNameOptions.Type,
	}
	records, response, err := service.listObjects(listObjectsOptions)
	if records == nil || len(records.Records) == 0 {
		return nil, response, fmt.Errorf("object not found")
	}
	return &records.Records[0], response, err
}

type ObjectRefOptions struct {
	Href string
}

const (
	XMLNamespaceVCloud = "http://www.vmware.com/vcloud/v1.5"
	// Mime for undeploy vApp params
	MimeUndeployVappParams = "application/vnd.vmware.vcloud.undeployVAppParams+xml"
	// Mime for deploy vApp params
	MimeDeployVappParams = "application/vnd.vmware.vcloud.deployVAppParams+xml"
)

// Esempio di XML generato:
// <UndeployVAppParams xmlns="http://www.vmware.com/vcloud/v1.5">
//
//	<UndeployPowerAction>powerOff</UndeployPowerAction>
//
// </UndeployVAppParams>
type UndeployVAppParams struct {
	Xmlns               string `xml:"xmlns,attr"`
	UndeployPowerAction string `xml:"UndeployPowerAction,omitempty"`
}

type Task struct {
	Href            *string `json:"href"`            // nullable
	ID              *string `json:"id"`              // nullable
	Type            *string `json:"type"`            // nullable
	Name            *string `json:"name"`            // nullable
	Error           *string `json:"error"`           // nullable
	Status          *string `json:"status"`          // nullable
	Operation       *string `json:"operation"`       // nullable
	OperationName   *string `json:"operationName"`   // nullable
	StartTime       *string `json:"startTime"`       // nullable
	CancelRequested *bool   `json:"cancelRequested"` // nullable
}

func UnmarshalTask(m map[string]json.RawMessage, result interface{}) (err error) {
	obj := new(Task)
	err = core.UnmarshalPrimitive(m, "href", &obj.Href)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "id", &obj.ID)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "type", &obj.Type)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "name", &obj.Name)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "error", &obj.Error)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "status", &obj.Status)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "operation", &obj.Operation)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "operationName", &obj.OperationName)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "startTime", &obj.StartTime)
	if err != nil {
		return
	}
	err = core.UnmarshalPrimitive(m, "cancelRequested", &obj.CancelRequested)
	if err != nil {
		return
	}
	reflect.ValueOf(result).Elem().Set(reflect.ValueOf(obj))
	return
}

func (service *CloudDirectorV1) UndeployvApp(objectRefOptions *ObjectRefOptions) (task *Task, response *core.DetailedResponse, err error) {
	vu := &UndeployVAppParams{
		Xmlns:               XMLNamespaceVCloud,
		UndeployPowerAction: "powerOff",
	}
	builder := core.NewRequestBuilder(core.POST)
	_, err = builder.ResolveRequestURL(objectRefOptions.Href, `/action/undeploy`, nil)
	if err != nil {
		return
	}
	builder.AddHeader("Accept", "application/*+json;version="+APIVersion)
	builder.AddHeader("Content-Type", MimeUndeployVappParams)
	xmlbody, _ := xml.MarshalIndent(vu, "", "  ")
	builder.SetBodyContentString(string(xmlbody))
	request, err := builder.Build()
	if err != nil {
		return
	}
	var rawResponse map[string]json.RawMessage
	response, err = service.Request(request, &rawResponse)
	if err != nil {
		return
	}
	if rawResponse != nil {
		err = core.UnmarshalModel(rawResponse, "", &task, UnmarshalTask)
		if err != nil {
			return
		}
		response.Result = task
	}
	return
}

type DeployVAppParams struct {
	Xmlns   string `xml:"xmlns,attr"`
	PowerOn bool   `xml:"powerOn,attr"`
}

type DeployvAppOptions struct {
	Href string
}

func (service *CloudDirectorV1) DeployvApp(objectRefOptions *ObjectRefOptions) (task *Task, response *core.DetailedResponse, err error) {
	vu := &DeployVAppParams{
		Xmlns:   XMLNamespaceVCloud,
		PowerOn: true,
	}
	builder := core.NewRequestBuilder(core.POST)
	_, err = builder.ResolveRequestURL(objectRefOptions.Href, `/action/deploy`, nil)
	if err != nil {
		return
	}
	builder.AddHeader("Accept", "application/*+json;version="+APIVersion)
	builder.AddHeader("Content-Type", MimeDeployVappParams)
	xmlbody, _ := xml.MarshalIndent(vu, "", "  ")
	builder.SetBodyContentString(string(xmlbody))
	request, err := builder.Build()
	if err != nil {
		return
	}
	var rawResponse map[string]json.RawMessage
	response, err = service.Request(request, &rawResponse)
	if err != nil {
		return
	}
	if rawResponse != nil {
		err = core.UnmarshalModel(rawResponse, "", &task, UnmarshalTask)
		if err != nil {
			return
		}
		response.Result = task
	}
	return
}

type PowerOffVMOptions struct {
	Href string
}

type PowerActionOptions struct {
	Href   string
	Action string // powerOff or powerOn
}

func (service *CloudDirectorV1) VMPowerAction(powerActionOptions *PowerActionOptions) (task *Task, response *core.DetailedResponse, err error) {
	if powerActionOptions == nil {
		err = fmt.Errorf("powerActionOptions cannot be nil")
		return
	}
	if powerActionOptions.Href == "" {
		err = fmt.Errorf("Href cannot be empty")
		return
	}
	if powerActionOptions.Action != "powerOff" && powerActionOptions.Action != "powerOn" {
		err = fmt.Errorf("Action cannot be empty")
		return
	}
	builder := core.NewRequestBuilder(core.POST)
	_, err = builder.ResolveRequestURL(powerActionOptions.Href, "/power/action/"+powerActionOptions.Action, nil)
	if err != nil {
		return
	}
	builder.AddHeader("Accept", "application/*+json;version="+APIVersion)
	request, err := builder.Build()
	if err != nil {
		return
	}
	var rawResponse map[string]json.RawMessage
	response, err = service.Request(request, &rawResponse)
	if err != nil {
		return
	}
	if rawResponse != nil {
		err = core.UnmarshalModel(rawResponse, "", &task, UnmarshalTask)
		if err != nil {
			return
		}
		response.Result = task
	}
	return
}

func (service *CloudDirectorV1) PowerOffVM(objectRefOptions *ObjectRefOptions) (task *Task, response *core.DetailedResponse, err error) {
	return service.VMPowerAction(&PowerActionOptions{
		Href:   objectRefOptions.Href,
		Action: "powerOff",
	})
}

func (service *CloudDirectorV1) PowerOnVM(objectRefOptions *ObjectRefOptions) (task *Task, response *core.DetailedResponse, err error) {
	return service.VMPowerAction(&PowerActionOptions{
		Href:   objectRefOptions.Href,
		Action: "powerOn",
	})
}

type GetTaskOptions struct {
	Href string
}

func (service *CloudDirectorV1) GetTask(getTaskOptions *GetTaskOptions) (task *Task, response *core.DetailedResponse, err error) {
	builder := core.NewRequestBuilder(core.GET)
	_, err = builder.ResolveRequestURL(getTaskOptions.Href, "", nil)
	if err != nil {
		return
	}
	builder.AddHeader("Accept", "application/*+json;version="+APIVersion)
	request, err := builder.Build()
	if err != nil {
		return
	}
	var rawResponse map[string]json.RawMessage
	response, err = service.Request(request, &rawResponse)
	if err != nil {
		return
	}
	if rawResponse != nil {
		err = core.UnmarshalModel(rawResponse, "", &task, UnmarshalTask)
		if err != nil {
			return
		}
		response.Result = task
	}
	return
}

func (service *CloudDirectorV1) WaitTaskCompletion(task *Task) error {
	return service.WaitInspectTaskCompletion(task, 3*time.Second, service.Timeout)
}

// WaitInspectTaskCompletion waits for the completion of a task by periodically refreshing its status.
//
// Parameters:
// task:    the Task object to monitor
// delay:   the duration to wait between status checks
// timeout: the maximum duration to wait for task completion
//
// Return values:
// error: a non-nil error object if an error occurred or if the task did not complete successfully
func (service *CloudDirectorV1) WaitInspectTaskCompletion(task *Task, delay time.Duration, timeout time.Duration) error {

	if task == nil {
		return fmt.Errorf("cannot refresh, Object is empty")
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	howManyTimesRefreshed := 0
	for {
		select {
		case <-ctx.Done():
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				service.Log.Warn(
					"Timeout waiting for task completion",
					slog.String("component", "WaitInspectTaskCompletion"),
					slog.String("task.id", *task.ID),
					slog.String("timeout", timeout.String()),
					slog.Int("refreshes", howManyTimesRefreshed),
				)
				// return fmt.Errorf("timeout waiting for task completion after %s (refreshes=%d)", timeout, howManyTimesRefreshed)
				return nil
			}
			return fmt.Errorf("wait cancelled: %w", ctx.Err())
		default:
		}
		howManyTimesRefreshed++
		task, _, err := service.GetTask(&GetTaskOptions{
			Href: *task.Href,
		})
		if err != nil {
			return fmt.Errorf("%s : %s", "error retrieving task", err)
		}

		// If task is not in a waiting status we're done, check if there's an error and return it.
		if !isTaskRunning(*task.Status) {
			if *task.Status == "error" {
				var detail string
				if task.Error != nil {
					detail = *task.Error
				}
				return fmt.Errorf("task did not complete successfully: %s", detail)
			}
			return nil
		}

		// Task is still running, wait and refresh
		select {
		case <-ctx.Done():
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				service.Log.Warn(
					"Timeout waiting for task completion",
					slog.String("component", sdkName),
					slog.String("task.id", *task.ID),
					slog.String("timeout", timeout.String()),
					slog.Int("refreshes", howManyTimesRefreshed),
				)
				// return fmt.Errorf("timeout waiting for task completion after %s (refreshes=%d)", timeout, howManyTimesRefreshed)
				return nil
			}
			return fmt.Errorf("wait cancelled: %w", ctx.Err())
		case <-time.After(delay):
			//continue
		}
	}
}

// isTaskRunning returns true if the task has started or is about to start
func isTaskRunning(status string) bool {
	return status == "running" || status == "preRunning" || status == "queued"
}

// isTaskComplete returns true if the task has finished successfully or was interrupted, but not if it finished with error
func isTaskComplete(status string) bool {
	return status == "success" || status == "aborted"
}

// isTaskCompleteOrError returns true if the status has finished, regardless of the outcome
func isTaskCompleteOrError(status string) bool {
	return isTaskComplete(status) || status == "error"
}

// ---- Helpers ----

func validateURL(u string) error {
	s := strings.TrimSpace(u)
	if s == "" {
		return fmt.Errorf("URL empty")
	}
	if hasBadFirstOrLastChar(s) {
		return fmt.Errorf("The URL must not start/end with curly brackets or quotation marks; remove { } and \"")
	}
	return nil
}

func hasBadFirstOrLastChar(s string) bool {
	return strings.HasPrefix(s, "{") ||
		strings.HasSuffix(s, "}") ||
		strings.HasPrefix(s, "\"") ||
		strings.HasSuffix(s, "\"")
}

func joinURL(base, path string) string {
	b := strings.TrimRight(base, "/")
	p := strings.TrimLeft(path, "/")
	return b + "/" + p
}

func isJSONMime(ct string) bool {
	ct = strings.ToLower(strings.TrimSpace(ct))
	return strings.Contains(ct, "application/json") || strings.Contains(ct, "+json")
}

// Request invokes the specified HTTP request and returns the response.
//
// Parameters:
// req: the http.Request object that holds the request information
//
// result: a pointer to the operation result.  This should be one of:
//   - *io.ReadCloser (for a byte-stream type response)
//   - *<primitive>, *[]<primitive>, *map[string]<primitive>
//   - *map[string]json.RawMessage, *[]json.RawMessage
//
// Return values:
// detailedResponse: a DetailedResponse instance containing the status code, headers, etc.
//
// err: a non-nil error object if an error occurred
func (service *CloudDirectorV1) Request(req *http.Request, result interface{}) (detailedResponse *core.DetailedResponse, err error) {
	// Set default headers on the request.
	if service.DefaultHeaders != nil {
		for k, v := range service.DefaultHeaders {
			req.Header.Set(k, strings.Join(v, ""))
		}

		// After setting the default headers, make one final check to see if the user
		// specified the "Host" header within the default headers.
		// This needs to be handled separately because it will be ignored by
		// the Request.Write() method.
		host := service.DefaultHeaders.Get("Host")
		if host != "" {
			req.Host = host
		}
	}

	// Add the default User-Agent header if not already present.
	userAgent := req.Header.Get(headerNameUserAgent)
	if userAgent == "" {
		req.Header.Add(headerNameUserAgent, service.UserAgent)
	}

	// Add authentication to the outbound request.
	if core.IsNil(service.Auth) {
		err = errors.New(core.ERRORMSG_NO_AUTHENTICATOR)
		return
	}

	service.Auth.Authenticate(req)

	// If debug is enabled, then dump the request.
	if service.Log.Enabled(context.Background(), slog.LevelDebug) {
		buf, dumpErr := httputil.DumpRequestOut(req, !core.IsNil(req.Body))
		if dumpErr == nil {
			service.Log.Debug("Dump Request", slog.String("request", core.RedactSecrets(string(buf))))
		} else {
			service.Log.Debug("error while attempting to log outbound request", slog.String("error", dumpErr.Error()))
		}
	}

	// Invoke the request, then check for errors during the invocation.
	service.Log.Debug("Sending HTTP request message...")
	var httpResponse *http.Response
	httpResponse, err = service.Client.Do(req)
	if err != nil {
		if strings.Contains(err.Error(), core.SSL_CERTIFICATION_ERROR) {
			err = errors.New(core.ERRORMSG_SSL_VERIFICATION_FAILED + "\n" + err.Error())
		}
		err = errors.New("no-connection-made" + "\n" + err.Error())
		return
	}
	service.Log.Debug("Received HTTP response message", slog.Int("status_code", httpResponse.StatusCode))

	// If debug is enabled, then dump the response.
	if service.Log.Enabled(context.Background(), slog.LevelDebug) {
		buf, dumpErr := httputil.DumpResponse(httpResponse, !core.IsNil(httpResponse.Body))
		if err == nil {
			service.Log.Debug("Response", slog.String("body", core.RedactSecrets(string(buf))))
		} else {
			service.Log.Debug("error while attempting to log inbound response", slog.String("error:", dumpErr.Error()))
		}
	}

	// If the operation was unsuccessful, then set up and return
	// the DetailedResponse and error objects appropriately.
	if httpResponse.StatusCode < 200 || httpResponse.StatusCode >= 300 {
		err = fmt.Errorf("request failed with status code %d", httpResponse.StatusCode)
		return
	}

	// Operation was successful and we are expecting a response, so process the response.
	detailedResponse, contentType := getDetailedResponseAndContentType(httpResponse)
	if !core.IsNil(result) {
		resultType := reflect.TypeOf(result).String()

		// If 'result' is a io.ReadCloser, then pass the response body back reflectively via 'result'
		// and bypass any further unmarshalling of the response.
		if resultType == "*io.ReadCloser" {
			rResult := reflect.ValueOf(result).Elem()
			rResult.Set(reflect.ValueOf(httpResponse.Body))
			detailedResponse.Result = httpResponse.Body
		} else {

			// First, read the response body into a byte array.
			defer httpResponse.Body.Close() // #nosec G307
			responseBody, readErr := io.ReadAll(httpResponse.Body)
			if readErr != nil {
				err = fmt.Errorf(core.ERRORMSG_READ_RESPONSE_BODY, readErr.Error())
				return
			}

			// If the response body is empty, then skip any attempt to deserialize and just return
			if len(responseBody) == 0 {
				return
			}

			// If the content-type indicates JSON, then unmarshal the response body as JSON.
			if core.IsJSONMimeType(contentType) {
				// Decode the byte array as JSON.
				decodeErr := json.NewDecoder(bytes.NewReader(responseBody)).Decode(result)
				if decodeErr != nil {
					// Error decoding the response body.
					// Return the response body in RawResult, along with an error.
					err = fmt.Errorf(core.ERRORMSG_UNMARSHAL_RESPONSE_BODY, decodeErr.Error())
					detailedResponse.RawResult = responseBody
					return
				}

				// Decode step was successful. Return the decoded response object in the Result field.
				detailedResponse.Result = reflect.ValueOf(result).Elem().Interface()
				return
			}

			// Check to see if the caller wanted the response body as a string.
			// If the caller passed in 'result' as the address of *string,
			// then we'll reflectively set result to point to it.
			if resultType == "**string" {
				responseString := string(responseBody)
				rResult := reflect.ValueOf(result).Elem()
				rResult.Set(reflect.ValueOf(&responseString))

				// And set the string in the Result field.
				detailedResponse.Result = &responseString
			} else if resultType == "*[]uint8" { // byte is an alias for uint8
				rResult := reflect.ValueOf(result).Elem()
				rResult.Set(reflect.ValueOf(responseBody))

				// And set the byte slice in the Result field.
				detailedResponse.Result = responseBody
			} else {
				// At this point, we don't know how to set the result field, so we have to return an error.
				// But make sure we save the bytes we read in the DetailedResponse for debugging purposes
				detailedResponse.Result = responseBody
				err = fmt.Errorf(core.ERRORMSG_UNEXPECTED_RESPONSE, contentType, resultType)
				return
			}
		}
	} else if !core.IsNil(httpResponse.Body) {
		// We weren't expecting a response, but we have a reponse body,
		// so we need to close it now since we're not going to consume it.
		_ = httpResponse.Body.Close()
	}

	return
}

// getDetailedResponseAndContentType starts to populate the DetailedResponse
// and extracts the Content-Type header value from the response.
func getDetailedResponseAndContentType(httpResponse *http.Response) (detailedResponse *core.DetailedResponse, contentType string) {
	if httpResponse != nil {
		contentType = httpResponse.Header.Get(core.CONTENT_TYPE)
		detailedResponse = &core.DetailedResponse{
			StatusCode: httpResponse.StatusCode,
			Headers:    httpResponse.Header,
		}
	}
	return
}
