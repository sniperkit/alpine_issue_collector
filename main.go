package main

import (
	"encoding/json"
	"fmt"
	"github.com/eedevops/alpine_issue_collector/collectors"
	"github.com/eedevops/alpine_issue_collector/model"
	"github.com/eedevops/alpine_issue_collector/utils"
)

func main() {

	// Step 1: Get data from government CVE database

	path, err := utils.DownloadAndExtractFile(utils.ARCHIVEFILE, utils.EXTRACTEDFILE, utils.GOVCVEURL)
	if err != nil {
		fmt.Printf(err.Error())
	}
	fmt.Printf("Got path: %s\n", path)

	govtNVDentries, err := utils.ReadEntries(utils.EXTRACTEDFILE)
	if err != nil {
		fmt.Printf("error when getting cve entries: %s\n", err.Error())
	}
	/*for i := 0; i< len(govtNVDentries); i ++{
		fmt.Printf("%s\n", govtNVDentries[i].Name)
		for _, product := range govtNVDentries[i].Packages {
		fmt.Printf("%s version %s\n", product.Name, product.Version)
		}
	}*/

	// Step 2: Read all packages from Alpine Package Database

	c1 := collectors.NewDefaultAlpinePackageCollector()

	packages, err := c1.Collect()

	if err != nil {
		fmt.Println("Error collecting alpine packages")
		return
	}

	data, err := json.MarshalIndent(packages, "", "  ")

	if err != nil {
		fmt.Println("Error marshalling")
		return
	}

	// Pretty print the packages
	//fmt.Println(string(data))
	packagesVersionsMap := map[string][]model.AlpinePackageVersionDetails{}
	err = json.Unmarshal(data, &packagesVersionsMap)
	if err != nil {
		fmt.Println("error:", err)
	}
	// TODO: Step 3. Filter out items in NVD dataset that don't match Alpine packages / version / architecture
	fmt.Printf("\n### ALPINE PACKAGES 		###		%d	\n", len(packagesVersionsMap))
	fmt.Printf("### GOVERNMENT NVDS 		###		%d	\n", len(govtNVDentries))

	filteredNVDs := utils.ExtractMatchingAlpinePackagesAndGOVData(packagesVersionsMap, govtNVDentries)
	fmt.Printf("### MATCHED PACKAGES STEP 3 	###		%d	\n", len(filteredNVDs))

	// TODO: Step 4. Grab issues from Alpine issues page, cross reference CVE information, inject metadata
	//issues :=utils.GetUniqueCVEListFromAlpineURL()
	//finalNVDs := utils.ExtractMatchingAlpineIssueCVESandGovData(issues, filteredNVDs)
	//fmt.Printf("### MATCHED PACKAGES STEP 4 	###		%d	\n", len(finalNVDs))
	// TODO: Step 5. Upload file to github.com or S3 file server
	// Temporarily write the final results to a local file
	finalData, err := json.MarshalIndent(filteredNVDs, "", "  ")

	if err != nil {
		fmt.Println("Error marshalling")
		return
	}
	utils.WriteDataToFinalOutputJSONFile(finalData)
}
