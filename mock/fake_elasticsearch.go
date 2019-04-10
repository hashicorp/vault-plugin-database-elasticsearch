package mock

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
)

const (
	username = "fizz"
	password = "buzz"
)

func Elasticsearch() *FakeElasticsearch {
	return &FakeElasticsearch{
		Roles: make(map[string]map[string]interface{}),
		Users: make(map[string]map[string]interface{}),
	}
}

type FakeElasticsearch struct {
	Roles map[string]map[string]interface{}
	Users map[string]map[string]interface{}
}

func (f *FakeElasticsearch) HandleRequests(w http.ResponseWriter, r *http.Request) {
	reqUsername, reqPassword, _ := r.BasicAuth()
	if reqUsername != username || reqPassword != password {
		w.WriteHeader(401)
		return
	}

	bodyBytes, err := ioutil.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(400)
		w.Write([]byte(fmt.Sprintf("unable to read request body due to %s", err.Error())))
		return
	}
	body := make(map[string]interface{})
	if len(bodyBytes) > 0 {
		if err := json.Unmarshal(bodyBytes, &body); err != nil {
			w.WriteHeader(400)
			w.Write([]byte(fmt.Sprintf("unable to unmarshal %s due to %s", bodyBytes, err.Error())))
			return
		}
	}
	objName := strings.Split(r.URL.Path, "/")[4]
	switch {
	case strings.HasPrefix(r.URL.Path, "/_xpack/security/role/"):
		switch r.Method {
		case http.MethodPost:
			if _, found := f.Roles[objName]; found {
				w.Write([]byte(fmt.Sprintf(createRoleResponseTpl, "false")))
			} else {
				w.Write([]byte(fmt.Sprintf(createRoleResponseTpl, "true")))
			}
			f.Roles[objName] = body
			return
		case http.MethodGet:
			role, found := f.Roles[objName]
			if !found {
				w.WriteHeader(404)
				return
			}
			roleJson, _ := json.Marshal(role)
			w.Write([]byte(fmt.Sprintf(getRoleResponseTpl, objName, roleJson)))
			return
		case http.MethodDelete:
			if _, found := f.Roles[objName]; found {
				w.Write([]byte(fmt.Sprintf(deleteRoleResponseTpl, "true")))
			} else {
				w.Write([]byte(fmt.Sprintf(deleteRoleResponseTpl, "false")))
			}
			delete(f.Roles, objName)
			return
		}
	case strings.HasPrefix(r.URL.Path, "/_xpack/security/user/") && !strings.HasSuffix(r.URL.Path, "_password"):
		switch r.Method {
		case http.MethodPost:
			if _, found := f.Users[objName]; found {
				w.Write([]byte(fmt.Sprintf(createUserResponseTpl, "false", "false")))
			} else {
				w.Write([]byte(fmt.Sprintf(createUserResponseTpl, "true", "true")))
			}
			return
		case http.MethodDelete:
			if _, found := f.Users[objName]; found {
				w.Write([]byte(fmt.Sprintf(deleteUserResponseTpl, "true")))
			} else {
				w.Write([]byte(fmt.Sprintf(deleteUserResponseTpl, "false")))
			}
			return
		}
	case strings.HasPrefix(r.URL.Path, "/_xpack/security/user/") && strings.HasSuffix(r.URL.Path, "_password"):
		switch r.Method {
		case http.MethodPost:
			if body["password"].(string) == "" {
				w.WriteHeader(400)
				w.Write([]byte("password is required"))
				return
			}
			w.Write([]byte(changePasswordResponse))
			return
		}
	}
	// We received an unexpected request.
	w.WriteHeader(404)
	w.Write([]byte(fmt.Sprintf("%s to %s is unsupported", r.Method, r.URL.Path)))
}

func (f *FakeElasticsearch) Username() string {
	return username
}

func (f *FakeElasticsearch) Password() string {
	return password
}
