/*
Sniperkit-Bot
- Status: analyzed
*/

package utils

import (
	//"compress/gzip"
	"encoding/xml"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"

	log "github.com/sirupsen/logrus"

	"github.com/sniperkit/snk.fork.eedevops-alpine_issue_collector/model"

	//"path/filepath"
	"compress/gzip"
	"strconv"
	"strings"
	"time"
)

const (
	EXTRACTEDFILE       = "data/cve.xml"
	GOVCVEURL           = "http://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-%s.xml.gz"
	DEFAULT_FILE_STRING = "cve.xml"
)

func init() {
	log.SetLevel(log.WarnLevel)
}
func GetDataFeedNames() []string {
	var dataFeedNames []string
	for y := 2002; y <= time.Now().Year(); y++ {
		dataFeedNames = append(dataFeedNames, strconv.Itoa(y))
	}
	return dataFeedNames
}

func ReadEntries(filePath string) ([]model.NVDEntry, error) {
	dat, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	nvd := model.NVD{}
	err = xml.Unmarshal([]byte(dat), &nvd)
	if err != nil {
		return nil, err
	}
	//process the packages for each entry and get the package name and version.
	for i, entry := range nvd.Entries {
		nvd.Entries[i].Packages = make(map[string]model.SoftwarePackage)
		for _, product := range entry.Products.ProductStrings {
			var version string
			words := strings.Split(product, ":")
			//			afflicted_software := model.SoftwarePackage{}

			productLen := len(words)
			name := ""
			if productLen > 3 {
				name = words[3]
			}

			if name == "" {
				fmt.Errorf("Length of product %s is %d... skipping", product, productLen)
				continue
			}
			if productLen > 4 {
				version = words[4]
			} else {
				version = "unknown"
			}
			_, exists := nvd.Entries[i].Packages[name]
			if !exists {
				nvd.Entries[i].Packages[name] = model.SoftwarePackage{Name: name}
			}
			tmp_package := nvd.Entries[i].Packages[name]
			tmp_package.Versions = append(tmp_package.Versions, version)
			nvd.Entries[i].Packages[name] = tmp_package

			//			nvd.Entries[i].Packages = append(nvd.Entries[i].Packages, afflicted_software)
		}
	}
	/*fmt.Printf("first cve = %s\n", nvd.Entries[5].Name)
	for _, pack := range nvd.Entries[5].Packages {
		fmt.Printf("package name =  %s\nversions:\n", pack.Name)
		for _, version := range pack.Versions {
			fmt.Printf("%s\n", version)
		}
	}*/
	return nvd.Entries, nil
}
func DownloadAndExtractFile(downloadDir string, url string, verbose bool) ([]string, error) {

	downloadDir = strings.TrimRight(downloadDir, "/")
	// Get the data
	df := GetDataFeedNames()
	localCompressedFileNames := []string{}
	for i, de := range df {
		// Create the file
		compressedFileName := fmt.Sprintf("%s/%s-%d.gz", downloadDir, DEFAULT_FILE_STRING, i)
		out, err := os.Create(compressedFileName)
		if err != nil {
			fmt.Errorf("Could not create compressed file %s", compressedFileName)
			continue
		}

		endpoint := fmt.Sprintf(GOVCVEURL, de)
		resp, err := http.Get(endpoint)
		if err != nil {
			fmt.Errorf("Could not download (get) file %s", endpoint)
			continue
		}

		// Writer the body to file
		if verbose {
			log.Debug(fmt.Printf("Processing GOV page %s\n", endpoint))
		}
		_, err = io.Copy(out, resp.Body)
		if err != nil {
			fmt.Errorf("Could not write download of file %s into %s", compressedFileName, endpoint)
			continue
		}

		localCompressedFileNames = append(localCompressedFileNames, compressedFileName)
		out.Close()
		resp.Body.Close()
	}

	extractedFileNames := []string{}
	for i, compressedFileName := range localCompressedFileNames {
		// open archive file
		reader, err := os.Open(compressedFileName)
		if err != nil {
			fmt.Errorf("Could not open compressed file %s", compressedFileName)
			continue
		}

		archive, err := gzip.NewReader(reader)
		if err != nil {
			fmt.Errorf("Could not read compressed file %s", compressedFileName)
			continue
		}

		//extract archive

		parts := strings.Split(compressedFileName, "-")
		extractedFileName := ""
		if len(parts) == 2 {
			otherParts := strings.Split(parts[0], ".")

			if len(otherParts) == 2 {
				extractedFileName = fmt.Sprintf("%s-%d.%s", otherParts[0], i, otherParts[1])
			}

		}

		if extractedFileName == "" {
			fmt.Errorf("Could not generate local extracted file name for %s", compressedFileName)
			continue
		}

		writer, err := os.Create(extractedFileName)
		if err != nil {
			fmt.Errorf("Could not create extracted file %s", extractedFileName)
			continue
		}

		_, err = io.Copy(writer, archive)
		if err != nil {
			fmt.Errorf("Could not copy file %s to %s, error = %s", compressedFileName, extractedFileName, err.Error())
			continue
		}
		// remove tha archive file and return the extracted file
		os.Remove(compressedFileName)
		extractedFileNames = append(extractedFileNames, extractedFileName)
		reader.Close()
		archive.Close()
		writer.Close()
	}

	return extractedFileNames, nil
}

func Collect(verbose bool) ([]model.NVDEntry, error) {
	allEntries := []model.NVDEntry{}

	paths, err := DownloadAndExtractFile("/tmp", GOVCVEURL, verbose)
	if err != nil {
		fmt.Printf(err.Error())
		return allEntries, err
	}

	for _, xmlFile := range paths {
		entries, err := CollectFromSingleFile(verbose, xmlFile)
		if nil == err {
			allEntries = append(allEntries, entries...)
		}
		/*
			if verbose {
				fmt.Printf("Reading entries from file %s\n", xmlFile)
			}
			entries, err := ReadEntries(xmlFile)

			if err != nil {
				fmt.Errorf("Could not read NVD entries from file %s\n", xmlFile)
				continue
			}
			if verbose {
				fmt.Printf("Found %d entries from file %s\n", len(entries), xmlFile)
			}
			allEntries = append(allEntries, entries...)
			if verbose {
				fmt.Printf("Length of all entries = %d\n", len(allEntries))
			}
			os.RemoveAll(xmlFile)
		*/
		os.RemoveAll(xmlFile)

	}

	return allEntries, nil
}

func CollectFromSingleFile(verbose bool, xmlFile string) ([]model.NVDEntry, error) {
	allEntries := []model.NVDEntry{}
	if verbose {
		fmt.Printf("Reading entries from file %s\n", xmlFile)
	}
	entries, err := ReadEntries(xmlFile)

	if err != nil {
		fmt.Errorf("Could not read NVD entries from file %s\n", xmlFile)
		return entries, err
	}
	if verbose {
		fmt.Printf("Found %d entries from file %s\n", len(entries), xmlFile)
	}
	allEntries = append(allEntries, entries...)
	if verbose {
		fmt.Printf("Length of all entries = %d\n", len(allEntries))
	}
	return allEntries, nil
}
