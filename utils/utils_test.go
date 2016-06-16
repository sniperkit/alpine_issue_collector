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
//get the government issues list
//filter them so that we only see the ones relevant to alpine packages
//convert them to the json format expected by clair
//verify each step with predefined data, so that we get predictable results

//get packages
func init() {
	log.SetLevel(log.WarnLevel)
}
func TestCollector(t *testing.T) {
	c1 := collectors.NewDefaultAlpinePackageCollector()
	c1.SetMaxNumberPages(2) //get just 2 pages instead of all
	packages, err := c1.Collect(false)
	//make sure the collector collected
	assert.Nil(t, err)
	assert.NotEmpty(t, packages)
	global_packages = packages
	return
}

func TestNVDCollection(t *testing.T) {
	govtNVDentries, err := Collect(false)
	//make sure NVD data is collected
	assert.Nil(t, err)
	assert.NotEmpty(t, govtNVDentries)
	global_issues = govtNVDentries
	return
}

/*
func TestFilter(t *testing.T) {
	assert.NotEmpty(t, global_issues)
	assert.NotEmpty(t, global_packages)
	filteredNVDs := ExtractMatchingAlpinePackagesAndGOVData(global_packages, global_issues)
	assert.NotEmpty(t, filteredNVDs)
	global_filtered_issues = filteredNVDs
	return
}

func TestConvertNVDToClair(t *testing.T) {
	assert.NotEmpty(t, global_filtered_issues)
	assert.NotEmpty(t, global_packages)
	jsonData := ConvertNVDToClair(global_packages, global_filtered_issues)
	assert.NotEmpty(t, jsonData)
	return
}
*/
