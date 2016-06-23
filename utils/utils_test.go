package utils

import (
	"encoding/json"
	"fmt"
	log "github.com/Sirupsen/logrus"
	"github.com/eedevops/alpine_issue_collector/collectors"
	"github.com/eedevops/alpine_issue_collector/model"
	"github.com/eedevops/alpine_issue_collector/uploaders"
	. "github.com/smartystreets/goconvey/convey"
	"io/ioutil"
	"net/http"
	"os"
	"regexp"
	"testing"
	"time"
)

var (
	global_packages        collectors.AlpinePackageDictionary
	global_issues          []model.NVDEntry
	global_filtered_issues []model.NVDEntry
	global_json_data       model.JsonData
	global_json_filename   string
)

//get packages
func init() {
	log.SetLevel(log.InfoLevel)
}
func TestCollector(t *testing.T) {
	Convey("Get all alpine packages\n", t, func() {
		c1 := collectors.NewDefaultAlpinePackageCollector()
		c1.SetMaxNumberPages(6) //get just 2 pages instead of all
		packages, err := c1.Collect(false)
		So(err, ShouldBeNil)
		So(packages, ShouldNotBeEmpty)
	})
}

//get the government issues list

func TestNVDCollection(t *testing.T) {
	Convey("Pull issues from CVE repository, this will take a while...\n", t, func() {
		govtNVDentries, err := Collect(false)
		So(err, ShouldBeNil)
		So(govtNVDentries, ShouldNotBeEmpty)
		global_issues = govtNVDentries
	})
}

//get test cve issues
func TestLoadTestData(t *testing.T) {
	Convey("Get mock data from file\n", t, func() {
		NVDEntries, err := CollectFromSingleFile(false, "test_data.xml")
		So(err, ShouldBeNil)
		So(NVDEntries, ShouldNotBeEmpty)
		global_issues = NVDEntries
	})

	//create a package for subversion
	Convey("Create package for mock data", t, func() {
		var alpine_packages []collectors.AlpinePackage
		var dictionary collectors.AlpinePackageDictionary
		var pack collectors.AlpinePackage

		pack = make(map[string]string)
		pack["bdate"] = "2016-06-1520:47:42"
		pack["package"] = "subversion"
		pack["url"] = "URL"
		pack["license"] = "apachebsd"
		pack["branch"] = "edge"
		pack["maintainer"] = "NatanaelCopa"
		pack["version_release"] = "r1"
		pack["version"] = "1.9.4"
		pack["repo"] = "main"
		pack["arch"] = "x86"
		alpine_packages = append(alpine_packages, pack)

		pack = make(map[string]string)
		pack["license"] = "apachebsd"
		pack["branch"] = "edge"
		pack["arch"] = "x86_64"
		pack["bdate"] = "2016-06-1520:47:11"
		pack["package"] = "subversion"
		pack["version_release"] = "r1"
		pack["version"] = "1.9.4"
		pack["url"] = "URL"
		pack["repo"] = "main"
		pack["maintainer"] = "NatanaelCopa"

		alpine_packages = append(alpine_packages, pack)

		dictionary = make(map[string][]collectors.AlpinePackage)
		dictionary[pack["package"]] = alpine_packages
		global_packages = dictionary
		//no assertions, because this is just creating a dictionary
	})
}

func TestFilter(t *testing.T) {
	Convey("Filter issues from file by alpine package\n", t, func() {
		So(global_issues, ShouldNotBeEmpty)
		So(global_packages, ShouldNotBeEmpty)
		filteredNVDs := ExtractMatchingAlpinePackagesAndGOVData(global_packages, global_issues)
		So(filteredNVDs, ShouldNotBeEmpty)
		global_filtered_issues = filteredNVDs
	})
}

func TestConvertNVDToClair(t *testing.T) {
	Convey("Convert issues to the format clair expects\n", t, func() {
		So(global_filtered_issues, ShouldNotBeEmpty)
		So(global_packages, ShouldNotBeEmpty)
		jsonData := ConvertNVDToClair(global_packages, global_filtered_issues)
		So(jsonData, ShouldNotBeEmpty)
		vuln := jsonData["subversion"]
		//add checks for all the fields of the json data, since we can control all the data that goes in
		So(vuln, ShouldNotBeEmpty)
		issue := vuln["CVE-2007-2448"]
		So(issue.Releases, ShouldNotBeEmpty)
		release := issue.Releases["alpine:edge"]
		So(release.AffectedVersions, ShouldNotBeEmpty)
		So(release.AffectedVersions[0], ShouldEqual, "1.9.4-r1")
		So(release.Status, ShouldEqual, "open")
		So(release.Urgency, ShouldEqual, "high**")
		global_json_data = jsonData
	})
}

func TestWriteToFile(t *testing.T) {
	Convey("Write the filtered issues to a local file\n", t, func() {
		var fileData model.JsonData
		So(global_json_data, ShouldNotBeEmpty)
		finalData, err := json.MarshalIndent(global_json_data, "", "  ")
		So(err, ShouldBeNil)
		So(finalData, ShouldNotBeEmpty)
		jsonFileName, err := WriteDataToFinalOutputJSONFile("/tmp", finalData)
		So(err, ShouldBeNil)
		So(jsonFileName, ShouldNotBeEmpty)
		//get json from file
		file, err := ioutil.ReadFile(jsonFileName)
		So(err, ShouldBeNil)
		So(file, ShouldNotBeEmpty)
		json.Unmarshal(file, &fileData)
		So(fileData, ShouldNotBeEmpty)
		vuln := fileData["subversion"]
		//add checks for all the fields of the json data, since we can control all the data that goes in
		So(vuln, ShouldNotBeEmpty)
		issue := vuln["CVE-2007-2448"]
		So(issue.Releases, ShouldNotBeEmpty)
		release := issue.Releases["alpine:edge"]
		So(release.AffectedVersions, ShouldNotBeEmpty)
		So(release.AffectedVersions[0], ShouldEqual, "1.9.4-r1")
		So(release.Status, ShouldEqual, "open")
		So(release.Urgency, ShouldEqual, "high**")
		global_json_filename = jsonFileName
	})
}

func TestUploadFile(t *testing.T) {
	Convey("Upload our clair file to github\n", t, func() {
		var fileData model.JsonData
		// TODO: Step 7. Upload file to github.com or S3 file server
		repoPath := fmt.Sprintf("/tmp/alpine-git-test-repo-%d", time.Now().Unix())
		deployKey := os.Getenv("ALPINE_DATA_COLLECTOR_SSH_DEPLOY_KEY")
		branchName := os.Getenv("CVE_REPO_BRANCHNAME")
		remoteRepoUri := os.Getenv("CVE_REPO_REMOTE_URI")
		origin := os.Getenv("CVE_REPO_REMOTE_ORIGIN")
		fileUrl := "https://raw.githubusercontent.com/eedevops/alpine-cve-db/testing/alpine-linux-package-cve-db.json"

		err := uploaders.ConfigureSshEnv(deployKey)
		if err != nil {
			log.Fatalf("Could not configure ssh environment for git, error = %s", err.Error())
		}

		if branchName == "" {
			// default
			branchName = "testing"
		}

		if remoteRepoUri == "" {
			// default
			remoteRepoUri = "git@github.com:eedevops/alpine-cve-db.git"
		}

		if origin == "" {
			origin = "origin"
		}

		commitMsg := fmt.Sprintf("(Alpine Issue Collector Test) - changes to the alpine package / CVE list @ %s", time.Now().String())
		gitConfig := uploaders.NewGitRepoConfig(
			repoPath,
			branchName,
			commitMsg,
			remoteRepoUri,
			origin,
			"",
		)

		err = uploaders.Upload(global_json_filename, *gitConfig)
		So(err, ShouldBeNil)

		//then download the file and verify that it contains what it should contain
		resp, err := http.Get(fileUrl)
		So(err, ShouldBeNil)
		So(resp.StatusCode, ShouldNotEqual, 400)
		defer resp.Body.Close()
		body, err := ioutil.ReadAll(resp.Body)
		So(err, ShouldBeNil)
		err = json.Unmarshal(body, &fileData)
		So(err, ShouldBeNil)
		So(fileData, ShouldNotBeEmpty)
		vuln := fileData["subversion"]
		So(vuln, ShouldNotBeEmpty)
		issue := vuln["CVE-2007-2448"]
		So(issue.Releases, ShouldNotBeEmpty)
		release := issue.Releases["alpine:edge"]
		So(release.AffectedVersions, ShouldNotBeEmpty)
		So(release.AffectedVersions[0], ShouldEqual, "1.9.4-r1")
		So(release.Status, ShouldEqual, "open")
		So(release.Urgency, ShouldEqual, "high**")
	})
}

//this is the cleanup function, it should always run last
func TestCleanup(t *testing.T) {
	Convey("We make sure that we can cleanup after all tests.", t, func() {
		err := os.RemoveAll(global_json_filename)
		So(err, ShouldBeNil)
		regex := regexp.MustCompile(`^/tmp/resultNVD-final-(\d+)\.json$`)
		matches := regex.FindStringSubmatch(global_json_filename)
		if len(matches) > 1 {
			dirname := "/tmp/alpine-git-test-repo-" + matches[1]
			os.RemoveAll(dirname)
		} else {
			fmt.Printf("no matches\n")
		}

	})
}
