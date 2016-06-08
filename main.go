package main

import (
	"encoding/json"
	"fmt"
	"github.com/eedevops/alpine_issue_collector/collectors"
	"github.com/eedevops/alpine_issue_collector/utils"
)

func main() {

	// Step 1: Get data from government CVE database
	govtNVDentries, err := utils.Collect()
	if err != nil {
		fmt.Printf("error when getting cve entries: %s\n", err.Error())
	}

	// Step 2: Read all packages from Alpine Package Database

	c1 := collectors.NewDefaultAlpinePackageCollector()

	c1.SetMaxNumberPages(0)

	packages, err := c1.Collect()

	if err != nil {
		fmt.Println("Error collecting alpine packages")
		return
	}

	// Step 3. Filter out items in NVD dataset that don't match Alpine packages / version / architecture

	filteredNVDs := utils.ExtractMatchingAlpinePackagesAndGOVData(packages, govtNVDentries)

	// TODO: Step 4. Grab issues from Alpine issues page, cross reference CVE information, inject metadata
	//issues :=utils.GetUniqueCVEListFromAlpineURL()
	//finalNVDs := utils.ExtractMatchingAlpineIssueCVESandGovData(issues, filteredNVDs)

	fmt.Printf("### MATCHED PACKAGES STEP 4 	###		%d	\n", len(filteredNVDs))

	// Step 5: Convert to Clair-consumable format
	// FIXME: a lot of values are being hardcoded, should extract from alpine packages or from other sources.
	almostFinalData := utils.ConvertNVDToClair(packages, filteredNVDs)
	fmt.Printf("### CLAIR READY PACKAGE LIST STEP 5 	###		%d	\n", len(almostFinalData))

	// Step 6: Write Clair-consumable json to file before uploading.
	finalData, err := json.MarshalIndent(almostFinalData, "", "  ")

	if err != nil {
		fmt.Println("Error marshalling")
		return
	}

	if jsonFileName, err := utils.WriteDataToFinalOutputJSONFile("/tmp", finalData); err != nil {
		fmt.Println(jsonFileName)
		// TODO: Step 7. Upload file to github.com or S3 file server

		// TODO: Step 8. Remove file
		// os.RemoveAll(jsonFileName)
	}
}
