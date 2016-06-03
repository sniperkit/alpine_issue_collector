package utils

import (
	"encoding/json"
	"fmt"
	"github.com/eedevops/alpine_issue_collector/model"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"
)

/*
Get packages from alpine with versions
Match with CVEs
Get CVEs from alpine issues
Mix and match above
Output JSON
*/
const (
	ALPINEBUGURL           = "http://bugs.alpinelinux.org/projects/alpine/issues.csv?c%5B%5D=project&c%5B%5D=tracker&c%5B%5D=status&c%5B%5D=priority&c%5B%5D=subject&c%5B%5D=assigned_to&c%5B%5D=updated_on&f%5B%5D=&group_by=&set_filter=1&utf8=%E2%9C%93"
	ALPINEPACKAGEURL       = "http://pkgs.alpinelinux.org/packages"
	PACKAGEVERSIONFILEPATH = "../data/packages_versions.json"
	FINALJSONFILE          = "result/resultNVD.json"
)

func GetDataFromAlpineIssuesUrl(url string) ([]string, error) {
	response, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	contents, err := ioutil.ReadAll(response.Body)
	if err != nil {
		fmt.Printf("%s", err)
		os.Exit(1)
	}
	strings := strings.Split(string(contents), ",")
	return strings, nil
}
func GetDataFromAlpinePackageUrl(url string) ([]string, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	contents, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("%s", err)
		os.Exit(1)
	}
	//fmt.Printf(string(contents))

	aTagRegexp := regexp.MustCompile(`<a`)
	miniSlice := aTagRegexp.FindStringSubmatch(string(contents))
	for _, elem := range miniSlice {
		fmt.Printf("Elem = %s\n", elem)
	}

	return nil, nil
}

func GetDataFromAlpinePackages() {

	var wg sync.WaitGroup
	wg.Add(1)
	defer wg.Done()
	ticker := time.NewTicker(time.Second * 1)
	go func() {
		exec.Command("python", "-c", "parser.py")
		go func() {
			for t := range ticker.C {
				fmt.Printf("Processing data from alpine package URL at time: %s \n", t.String())

			}
		}()

	}()

	ticker.Stop()
	fmt.Println("Task completed")
}

func DetectNumberOfCves(list []string) []string {
	results := []string{}
	cveRegexp := regexp.MustCompile(`CVE-[0-9]{4}-[0-9]{4}`)
	for _, elem := range list {
		if strings.Contains(elem, "CVE") {
			miniSlice := cveRegexp.FindStringSubmatch(elem)
			results = append(results, miniSlice...)
		}

	}

	return results
}
func RemoveDuplicates(xs *[]string) {
	found := make(map[string]bool)
	j := 0
	for i, x := range *xs {
		if !found[x] {
			found[x] = true
			(*xs)[j] = (*xs)[i]
			j++
		}
	}
	*xs = (*xs)[:j]
}

func ProcessPackageVersionDataFromJsonFile() (map[string][]string, error) {

	myMap := map[string][]string{}
	file, e := ioutil.ReadFile(PACKAGEVERSIONFILEPATH)
	if e != nil {
		fmt.Printf("File error: %v\n", e)
		os.Exit(1)
	}
	fmt.Printf("%s\n", string(file))
	file2, _ := os.Open(PACKAGEVERSIONFILEPATH)
	fmt.Printf("Got %d\n", len(strings.Split(string(file), "],")))
	jsonParser := json.NewDecoder(file2)
	if err := jsonParser.Decode(&myMap); err != nil {
		fmt.Printf("parsing error", err.Error())
	}
	//fmt.Printf("Results: %v\n", myMapInJava)
	fmt.Printf("Processed %d\n`", len(myMap))
	return myMap, nil
}

func GetUniqueCVEListFromAlpineURL() []string {
	urlData, err := GetDataFromAlpineIssuesUrl(ALPINEBUGURL)

	if err != nil {
		fmt.Printf(string(err.Error()))
	}

	cves := DetectNumberOfCves(urlData)
	RemoveDuplicates(&cves)

	return cves
}
func GetPackagesFromAlpineUrl() []string {
	data, err := GetDataFromAlpinePackageUrl(ALPINEPACKAGEURL)
	if err != nil {
		fmt.Printf(string(err.Error()))
	}
	return data
}

func ExtractMatchingAlpinePackagesAndGOVData(alpine map[string][]model.AlpinePackageVersionDetails, government []model.NVDEntry) []model.NVDEntry {
	results := []model.NVDEntry{}
	for key, _ := range alpine {
		for _, gov := range government {
			for _, pkg := range gov.Packages {
				if key == pkg.Name {
					results = append(results, gov)
				}
			}
		}
	}
	return results
}
func ExtractMatchingAlpineIssueCVESandGovData(issueCVES []string, government []model.NVDEntry) []model.NVDEntry {
	results := []model.NVDEntry{}
	for _, cveName := range issueCVES {
		for _, gov := range government {
			if cveName == gov.Name {
				results = append(results, gov)
			}
		}
	}
	return results
}
func WriteDataToFinalOutputJSONFile(data []byte) error {
	// create file
	file, err := os.Create(FINALJSONFILE)
	if err != nil {
		return err
	}

	// Write the body to file
	_, err = file.Write(data)
	if err != nil {
		return err
	}
	return nil
}
