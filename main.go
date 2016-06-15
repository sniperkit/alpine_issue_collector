package main

import (
	"encoding/json"
	"fmt"
	"github.com/eedevops/alpine_issue_collector/collectors"
	"github.com/eedevops/alpine_issue_collector/uploaders"
	"github.com/eedevops/alpine_issue_collector/utils"
	"log"
	"os"
	"time"
)

const (
	NVD_COUNT_THRESHOLD              = 77000
	ALPINE_PACKAGE_COUNT_THRESHOLD   = 9487
	FILTERED_NVD_CVE_COUNT_THRESHOLD = 148
	VERBOSE                          = true
)

func main() {

	// Step 1: Get data from government CVE database
	govtNVDentries, err := utils.Collect()
	if err != nil {
		fmt.Printf("error when getting cve entries: %s\n", err.Error())
	}

	nvdTotal := len(govtNVDentries)

	if nvdTotal < NVD_COUNT_THRESHOLD {
		log.Fatalf("Retrieved less than %d nvd entries (only %d)\n", NVD_COUNT_THRESHOLD, nvdTotal)
	}

	log.Printf("### CVEs from NVD db = %d", nvdTotal)

	// Step 2: Read all packages from Alpine Package Database
	c1 := collectors.NewDefaultAlpinePackageCollector()

	c1.SetMaxNumberPages(0)

	packages, err := c1.Collect(VERBOSE)

	if err != nil {
		log.Fatalf("Error collecting alpine packages, error = %s", err.Error())
	}

	alpinePackageTotal := len(packages)

	if alpinePackageTotal < ALPINE_PACKAGE_COUNT_THRESHOLD {
		log.Fatalf("Retrieved less than %d alpine packages (only %d)\n", ALPINE_PACKAGE_COUNT_THRESHOLD, alpinePackageTotal)
	}

	log.Printf("### ALPINE PACKAGES = %d", alpinePackageTotal)

	// Step 3. Filter out items in NVD dataset that don't match Alpine packages / version / architecture
	filteredNVDs := utils.ExtractMatchingAlpinePackagesAndGOVData(packages, govtNVDentries)

	filteredTotal := len(filteredNVDs)

	if filteredTotal < FILTERED_NVD_CVE_COUNT_THRESHOLD {
		log.Fatalf("After matching / filtering, we have %d, but expected more than %d", filteredTotal, FILTERED_NVD_CVE_COUNT_THRESHOLD)
	}

	// TODO: Step 4. Grab issues from Alpine issues page, cross reference CVE information, inject metadata
	//issues :=utils.GetUniqueCVEListFromAlpineURL()
	//finalNVDs := utils.ExtractMatchingAlpineIssueCVESandGovData(issues, filteredNVDs)

	log.Printf("### MATCHED PACKAGES = %d \n", filteredTotal)

	// Step 5: Convert to Clair-consumable format
	// FIXME: a lot of values are being hardcoded, should extract from alpine packages or from other sources.
	almostFinalData := utils.ConvertNVDToClair(packages, filteredNVDs)

	log.Printf("### CLAIR READY PACKAGE LIST %d \n", len(almostFinalData))

	// Step 6: Write Clair-consumable json to file before uploading.
	finalData, err := json.MarshalIndent(almostFinalData, "", "  ")

	if err != nil {
		log.Fatalln("Error marshalling json data after NVD to Clair conversion.")
	}

	jsonFileName, err := utils.WriteDataToFinalOutputJSONFile("/tmp", finalData)

	if err != nil {
		log.Fatalf("Error trying to write json file %s with error = %s", jsonFileName, err.Error())
	}

	defer os.RemoveAll(jsonFileName)

	// TODO: Step 7. Upload file to github.com or S3 file server
	repoPath := fmt.Sprintf("/tmp/alpine-git-test-repo-%d", time.Now().Unix())
	deployKey := os.Getenv("ALPINE_DATA_COLLECTOR_SSH_DEPLOY_KEY")
	branchName := os.Getenv("CVE_REPO_BRANCHNAME")
	remoteRepoUri := os.Getenv("CVE_REPO_REMOTE_URI")
	origin := os.Getenv("CVE_REPO_REMOTE_ORIGIN")

	if err := uploaders.ConfigureSshEnv(deployKey); err != nil {
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

	commitMsg := fmt.Sprintf("(Alpine Issue Collector) - changes to the alpine package / CVE list @ %s", time.Now().String())
	gitConfig := uploaders.NewGitRepoConfig(
		repoPath,
		branchName,
		commitMsg,
		remoteRepoUri,
		origin,
		"",
	)

	fmt.Printf("Uploading filr %s to %s/%s/%s", jsonFileName, remoteRepoUri, origin, branchName)
	if err := uploaders.Upload(jsonFileName, *gitConfig); err != nil {
		log.Fatalf("Could not upload json file %s, error = %s\n", jsonFileName, err.Error())
	}

}
