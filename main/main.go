package main

import (
	"fmt"
	"github.com/eedevops/alpine_issue_collector/utils"
	//"strings"
)

func main() {

	//alpineCves := utils.GetUniqueCVEListFromAlpineURL()
	//govCveIds := utils.ReadFromXmlFile()

	//fmt.Printf("Got %d entries from alpine vulnerability database\n", len(alpineCves))
	//fmt.Printf("Got %d entries from government database\n", len(govCveIds))
	//utils.GetPackagesFromAlpineUrl()

	//utils.ExampleScrape()
	entries, err := utils.ReadEntries(utils.EXTRACTEDFILE)
	if err != nil {
		fmt.Printf("error when getting cve entries: %s\n", err.Error())
	}

	fmt.Printf("%s\n", entries[0].Name)
	for _, product := range entries[0].Packages {
		fmt.Printf("%s version %s\n", product.Name, product.Version)
	}

}
