// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package mock

const (
	createRoleResponseTpl = `{
	  "role": {
	    "created": %s 
	  }
	}`

	getRoleResponseTpl = `{
	  "%s": %s
	}`

	deleteRoleResponseTpl = `{
	  "found" : %s
	}`

	createUserResponseTpl = `{
	  "user": {
	    "created" : %s
	  },
	  "created": %s 
	}`

	changePasswordResponse = `{}`

	deleteUserResponseTpl = `{
	  "found" : %s
	}`
)
