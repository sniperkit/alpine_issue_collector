package utils

import (
	//"fmt"
	log "github.com/Sirupsen/logrus"
	"github.com/eedevops/alpine_issue_collector/collectors"
	"github.com/eedevops/alpine_issue_collector/model"
	"github.com/stretchr/testify/assert"
	"testing"
)

var (
	global_packages        collectors.AlpinePackageDictionary
	global_issues          []model.NVDEntry
	global_filtered_issues []model.NVDEntry
)

//maybe consider using something like convey?
//create a collector for this
//point the collector to a local file or a github file for testing
//filter them so that we only see the ones relevant to alpine packages
//convert them to the json format expected by clair
//verify each step with predefined data, so that we get predictable results

//get packages
func init() {
	log.SetLevel(log.InfoLevel)
}
func TestCollector(t *testing.T) {
	c1 := collectors.NewDefaultAlpinePackageCollector()
	c1.SetMaxNumberPages(6) //get just 2 pages instead of all
	packages, err := c1.Collect(false)
	//make sure the collector collected
	assert.Nil(t, err)
	assert.NotEmpty(t, packages)
	//global_packages = packages

	//done := false
	/*
		for line, pack := range packages {
			log.Info(line)
			if line == "subversion" {
				//log.Info(fmt.Sprintf("pack:%v", pack))

				for key, val := range pack {
					log.Info(fmt.Sprintf("key:%s value:%s", key, val))
				}
				//		done = true
			}
		}
	*/
}

/*
//get the government issues list
func TestNVDCollection(t *testing.T) {
	govtNVDentries, err := Collect(false)
	//make sure NVD data is collected
	assert.Nil(t, err)
	assert.NotEmpty(t, govtNVDentries)
	global_issues = govtNVDentries

}
*/
//get test cve issues
func TestLoadTestData(t *testing.T) {
	NVDEntries, err := CollectFromSingleFile(false, "test_data.xml")
	assert.NotEmpty(t, NVDEntries)
	assert.Nil(t, err)
	global_issues = NVDEntries
	/*
		for _, issue := range global_issues {
			log.Info(fmt.Sprintf("%v", issue))
		}
	*/
	//create a package for subversion
	var alpine_packages []collectors.AlpinePackage
	var dictionary collectors.AlpinePackageDictionary
	//type AlpinePackage map[string]string
	//type AlpinePackageDictionary map[string][]AlpinePackage
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
}
