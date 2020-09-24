package main

import (
	"log"
	"os"

	elasticsearch "github.com/hashicorp/vault-plugin-database-elasticsearch"
	"github.com/hashicorp/vault/api"
)

func main() {
	apiClientMeta := &api.PluginAPIClientMeta{}
	flags := apiClientMeta.FlagSet()
	flags.Parse(os.Args[1:])

	if err := elasticsearch.Run(); err != nil {
		log.Println(err)
		os.Exit(1)
	}
}
