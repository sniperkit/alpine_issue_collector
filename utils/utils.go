package utils

import (
	"encoding/json"
	"fmt"
	"github.com/eedevops/alpine_issue_collector/collectors"
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
	FINALJSONFILE_PREFIX   = "resultNVD-final"
	ALPINERELEASE          = "alpine:3.3.3"
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

func ExtractMatchingAlpinePackagesAndGOVData(alpinePackageDict collectors.AlpinePackageDictionary, nvds []model.NVDEntry) []model.NVDEntry {
	results := []model.NVDEntry{}
	for _, nvd := range nvds {
		// For each NVD for the government website
		includeNVD := false
		matchingSoftwarePackages := map[string]model.SoftwarePackage{}
		for govPackageIndex, pkg := range nvd.Packages {
			softwarePackageMatched := false
			// Check if the package is in the Alpine Packages dictionary using the package name
			// Use package name to identify
			if versions, ok := alpinePackageDict[govPackageIndex]; ok {
				// If the package from NVD is in the Alpine package list
				// then check if there are matching version.
				versionIntersection := map[string]string{}
				// For each version in the alpine package
				for _, version := range versions {
					// Check if it is present in the list of affected versions for the NVD package
					for _, packageVersion := range pkg.Versions {
						// If there is a match between versions, then mark this NVD / CVE entry
						// as one that should be added to the list of CVEs affecting alpine.
						if version["version"] == packageVersion {
							softwarePackageMatched = true
							versionAlpineStyle := version["version"]
							// Since alpine packages have a release suffix, append it before.
							if version["version_release"] != "" {
								versionAlpineStyle = fmt.Sprintf("%s-%s", versionAlpineStyle, version["version_release"])
							}
							versionIntersection[versionAlpineStyle] = versionAlpineStyle
						}
					}
				}

				// For each alpine package version that we found, add it to the
				// list of versions in the NVD / CVE package version list.
				// NOTE: we are overriding the original verisions of the NVD since we
				// don't need them anymore. We just need the ones that affect alpine.
				versionIntersections := []string{}
				for _, newVersion := range versionIntersection {
					versionIntersections = append(versionIntersections, newVersion)
				}
				pkg.Versions = versionIntersections
				nvd.Packages[govPackageIndex] = pkg

			}

			includeNVD = includeNVD || softwarePackageMatched

			// If we found that this NVD package matches a package in alpine,
			// then, add it to a map that will have only the matched packages.
			if softwarePackageMatched {
				matchingSoftwarePackages[govPackageIndex] = pkg
			}
		}

		// Override the packages for this NVD with just the packages matched with Alpine list.
		nvd.Packages = matchingSoftwarePackages
		// If we found a match between package versions in alpine dictionary and in the NVD / CVE list
		// then add it to the results.
		if includeNVD {
			results = append(results, nvd)
		}

		// next NVD / CVE
	}
	return results
}

func WriteDataToFinalOutputJSONFile(targetDir string, data []byte) (string, error) {
	// create file
	targetDir = strings.TrimRight(targetDir, "/")
	jsonFileName := fmt.Sprintf("%s/%s-%d.json", targetDir, FINALJSONFILE_PREFIX, time.Now().Unix())
	file, err := os.Create(jsonFileName)
	if err != nil {
		return jsonFileName, err
	}

	// Write the body to file
	_, err = file.Write(data)
	if err != nil {
		return jsonFileName, err
	}
	return jsonFileName, nil
}

func ConvertNVDToClair(alpinePackageDict collectors.AlpinePackageDictionary, entries []model.NVDEntry) model.JsonData {
	var data model.JsonData
	var lines []model.CVEFlatStructure
	data = make(map[string]map[string]model.JsonVuln)
	//loop through entries
	for _, entry := range entries {
		//loop through packages in current entry
		for _, pack := range entry.Packages {

			//create a new flat structure based on the current entry
			flat := model.CVEFlatStructure{CVE: entry.Name, Desc: entry.Description, Pack: pack}
			//push the current structure into the array
			lines = append(lines, flat)
		}
	}
	//loop through the flat structure array
	for _, line := range lines {
		//skip empty packages
		if line.Pack.Name == "" {
			continue
		}
		//check if the corresponding package exists, create it if it doesnt
		_, exists := data[line.Pack.Name]
		if !exists {
			data[line.Pack.Name] = make(map[string]model.JsonVuln)
		}
		//
		//need to figure out the status and urgency
		//hardcoding open and high** for now
		// added all versions
		for idx, _ := range alpinePackageDict[line.Pack.Name] {
			release := model.JsonRel{AffectedVersions: line.Pack.Versions, Status: "open", Urgency: "high**"}
			vuln := model.JsonVuln{Description: line.Desc}
			vuln.Releases = make(map[string]model.JsonRel)

			//hardcoding the release to alpine:3.3.3 for now

			releaseName := "alpine:" + alpinePackageDict[line.Pack.Name][idx]["branch"]
			vuln.Releases[releaseName] = release
			data[line.Pack.Name][line.CVE] = vuln
		}
		/*	releaseName := "alpine:"+alpinePackageDict[line.Pack.Name][0]["branch"]
			vuln.Releases[releaseName] = release*/

	}

	return data
}
