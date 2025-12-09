// Copyright IBM Corp. 2019, 2025
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"log"
	"os"

	elasticsearch "github.com/hashicorp/vault-plugin-database-elasticsearch"
	dbplugin "github.com/hashicorp/vault/sdk/database/dbplugin/v5"
)

func main() {
	if err := Run(); err != nil {
		log.Println(err)
		os.Exit(1)
	}
}

// Run starts serving the plugin
func Run() error {
	dbplugin.ServeMultiplex(elasticsearch.New)
	return nil
}
