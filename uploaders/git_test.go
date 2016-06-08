package uploaders_test

import (
	"fmt"
	gen "github.com/Pallinder/go-randomdata"
	"github.com/eedevops/alpine_issue_collector/uploaders"
	. "github.com/smartystreets/goconvey/convey"
	"os"
	"testing"
)

func TestGitUpload(t *testing.T) {

	Convey("Given that we setup our local environment to connect to remote repo via ssh", t, func() {
		deployKey := os.Getenv("ALPINE_DATA_COLLECTOR_SSH_DEPLOY_KEY")

		err := uploaders.ConfigureSshEnv(deployKey)
		So(err, ShouldBeNil)

		Convey("And given a mock json file to upload to github", func() {
			sillyName := gen.SillyName()

			now, tempFilepath, err := writeMockJsonFile()
			So(tempFilepath, ShouldNotBeBlank)
			So(err, ShouldBeNil)

			Convey("We should be able to commit and push the new file to github", func() {
				repoPath := fmt.Sprintf("/tmp/alpine-git-test-repo-%d", now.Unix())
				branchName := "testing"
				suffixMsg := fmt.Sprintf("This is a commit performed by %s @ %s", sillyName, now.String())
				commitMsg := fmt.Sprintf("'(Alpine Collector Test Suite) - %s'", suffixMsg)
				remoteRepoUri := "git@github.com:eedevops/alpine-cve-db.git"
				origin := "origin"

				config := uploaders.NewGitRepoConfig(
					repoPath,
					branchName,
					commitMsg,
					remoteRepoUri,
					origin,
					"",
				)

				err := uploaders.Upload(tempFilepath, *config)
				So(err, ShouldBeNil)

				Convey("And we should be able to cleanup the environment after upload", func() {
					err := uploaders.CleanupSshEnv()
					So(err, ShouldBeNil)

					err2 := uploaders.CleanupLocalRepo(config.RepoPath)
					So(err2, ShouldBeNil)

					err3 := os.RemoveAll(tempFilepath)
					So(err3, ShouldBeNil)

				})
			})
		})
	})
}
