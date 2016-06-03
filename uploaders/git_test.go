package uploaders_test

import (
	"encoding/json"
	"fmt"
	gen "github.com/Pallinder/go-randomdata"
	"github.com/eedevops/alpine_issue_collector/uploaders"
	. "github.com/smartystreets/goconvey/convey"
	"io/ioutil"
	"os"
	"testing"
	"time"
)

func TestGitUpload(t *testing.T) {

	Convey("Given that we setup our local environment to connect to remote repo via ssh", t, func() {
		deployKey := os.Getenv("ALPINE_DATA_COLLECTOR_SSH_DEPLOY_KEY")

		if err := uploaders.ConfigureSshEnv(deployKey); err != nil {
			ShouldBeNil(err)
		}

		Convey("And given a mock json file to upload to github", func() {
			name := gen.FullName(gen.RandomGender)
			sillyName := gen.SillyName()
			now := time.Now()
			timeString := now.String()
			timestamp := now.Unix()
			mockMap := map[string]string{
				"name":      name,
				"timestamp": timeString,
			}

			tempFilepath := fmt.Sprintf("/tmp/alpine-collector-uploader-mock-json-%d.json", timestamp)
			jsonData, err := json.MarshalIndent(mockMap, "", "  ")

			if err != nil {
				ShouldBeNil(err)
			}

			if err := ioutil.WriteFile(tempFilepath, jsonData, 0644); err != nil {
				ShouldBeNil(err)
			}

			Convey("We should be able to commit and push the new file to github", func() {
				repoPath := fmt.Sprintf("/tmp/alpine-git-test-repo-%d",timestamp)
				branchName := "testing"
				suffixMsg := fmt.Sprintf("This is a commit performed by %s @ %s", sillyName, timeString)
				commitMsg := fmt.Sprintf("'(Alpine Collector Test Suite) - %s'",suffixMsg)
				remoteRepoUri := "git@github.com:eedevops/alpine-cve-db.git"
				origin := "origin"

				config := uploaders.NewGitRepoConfig(
					repoPath,
					branchName,
					commitMsg,
					remoteRepoUri,
					origin,
				)

				if err := uploaders.Upload(tempFilepath, *config); err != nil {
					ShouldBeNil(err)
				}

				Convey("And we should be able to cleanup the environment after upload", func() {
					if err := uploaders.CleanupSshEnv(); err != nil {
						ShouldBeNil(err)
					}

					if err := uploaders.CleanupLocalRepo(config.RepoPath); err != nil {
						ShouldBeNil(err)
					}

					if err := os.RemoveAll(tempFilepath); err != nil {
						ShouldBeNil(err)
					}
				})
			})
		})
	})
}
