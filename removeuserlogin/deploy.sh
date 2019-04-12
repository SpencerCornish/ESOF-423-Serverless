gcloud functions deploy removeUserLogin \
                --runtime go111 \
                --trigger-event providers/cloud.firestore/eventTypes/document.delete \
                --trigger-resource projects/bsc-development/databases/(default)/documents/users/{userID} \
              --entry-point RemoveAuthUser