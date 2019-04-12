.PHONY: help
.DEFAULT_GOAL := help

help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

deploy:
	@gcloud functions deploy createUserLogin --entry-point CreateAuthUser --runtime go111 --trigger-http

deploy-del:
	@gcloud functions deploy removeUserLogin \
  		--runtime go111 \
  		--trigger-event providers/cloud.firestore/eventTypes/document.delete \
 		--trigger-resource projects/bsc-development/databases/(default)/documents/users/{userID}


