package utils

import (
	"encoding/json"
	"fmt"
	log "github.com/Sirupsen/logrus"
	"github.com/eedevops/alpine_issue_collector/collectors"
	"github.com/eedevops/alpine_issue_collector/model"
	"github.com/eedevops/alpine_issue_collector/uploaders"
	"github.com/stretchr/testify/assert"
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
	c1 := collectors.NewDefaultAlpinePackageCollector()
	c1.SetMaxNumberPages(6) //get just 2 pages instead of all
	packages, err := c1.Collect(false)
	assert.Nil(t, err)
	assert.NotEmpty(t, packages)

}

//get the government issues list

func TestNVDCollection(t *testing.T) {
	govtNVDentries, err := Collect(false)
	assert.Nil(t, err)
	assert.NotEmpty(t, govtNVDentries)
	global_issues = govtNVDentries

}

//get test cve issues
func TestLoadTestData(t *testing.T) {
	NVDEntries, err := CollectFromSingleFile(false, "test_data.xml")
	assert.NotEmpty(t, NVDEntries)
	assert.Nil(t, err)
	global_issues = NVDEntries
	//create a package for subversion
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
}

func TestFilter(t *testing.T) {
	assert.NotEmpty(t, global_issues)
	assert.NotEmpty(t, global_packages)
	filteredNVDs := ExtractMatchingAlpinePackagesAndGOVData(global_packages, global_issues)
	assert.NotEmpty(t, filteredNVDs)
	global_filtered_issues = filteredNVDs
}

func TestConvertNVDToClair(t *testing.T) {
	assert.NotEmpty(t, global_filtered_issues)
	assert.NotEmpty(t, global_packages)
	jsonData := ConvertNVDToClair(global_packages, global_filtered_issues)
	assert.NotEmpty(t, jsonData)
	vuln := jsonData["subversion"]
	//add checks for all the fields of the json data, since we can control all the data that goes in
	assert.NotEmpty(t, vuln)
	issue := vuln["CVE-2007-2448"]
	assert.NotEmpty(t, issue.Releases)
	release := issue.Releases["alpine:edge"]
	assert.NotEmpty(t, release.AffectedVersions)
	assert.Equal(t, "1.9.4-r1", release.AffectedVersions[0])
	assert.Equal(t, "open", release.Status)
	assert.Equal(t, "high**", release.Urgency)
	global_json_data = jsonData
}

func TestWriteToFile(t *testing.T) {
	var fileData model.JsonData
	assert.NotEmpty(t, global_json_data)
	finalData, err := json.MarshalIndent(global_json_data, "", "  ")
	assert.Nil(t, err)
	assert.NotEmpty(t, finalData)
	jsonFileName, err := WriteDataToFinalOutputJSONFile("/tmp", finalData)
	assert.Nil(t, err)
	assert.NotEmpty(t, jsonFileName)
	//get json from file
	file, err := ioutil.ReadFile(jsonFileName)
	assert.Nil(t, err)
	assert.NotEmpty(t, file)
	json.Unmarshal(file, &fileData)
	assert.NotEmpty(t, fileData)
	vuln := fileData["subversion"]
	//add checks for all the fields of the json data, since we can control all the data that goes in
	assert.NotEmpty(t, vuln)
	issue := vuln["CVE-2007-2448"]
	assert.NotEmpty(t, issue.Releases)
	release := issue.Releases["alpine:edge"]
	assert.NotEmpty(t, release.AffectedVersions)
	assert.Equal(t, "1.9.4-r1", release.AffectedVersions[0])
	assert.Equal(t, "open", release.Status)
	assert.Equal(t, "high**", release.Urgency)
	global_json_filename = jsonFileName

}

func TestUploadFile(t *testing.T) {
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
	assert.Nil(t, err)

	//then download the file and verify that it contains what it should contain
	resp, err := http.Get(fileUrl)

	assert.Nil(t, err)
	assert.NotEqual(t, 400, resp.StatusCode)
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	assert.Nil(t, err)
	err = json.Unmarshal(body, &fileData)
	assert.Nil(t, err)
	assert.NotEmpty(t, fileData)
	vuln := fileData["subversion"]
	assert.NotEmpty(t, vuln)
	issue := vuln["CVE-2007-2448"]
	assert.NotEmpty(t, issue.Releases)
	release := issue.Releases["alpine:edge"]
	assert.NotEmpty(t, release.AffectedVersions)
	assert.Equal(t, "1.9.4-r1", release.AffectedVersions[0])
	assert.Equal(t, "open", release.Status)
	assert.Equal(t, "high**", release.Urgency)
}

//this is the cleanup function, it should always run last
func TestCleanup(t *testing.T) {
	err := os.RemoveAll(global_json_filename)
	assert.Nil(t, err)
	regex := regexp.MustCompile(`^/tmp/resultNVD-final-(\d+)\.json$`)
	matches := regex.FindStringSubmatch(global_json_filename)
	if len(matches) > 1 {
		dirname := "/tmp/alpine-git-test-repo-" + matches[1]
		os.RemoveAll(dirname)
	} else {
		fmt.Printf("no matches\n")
	}
}
