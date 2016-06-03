package utils

import (
	"compress/gzip"
	"encoding/xml"
	"fmt"
	"github.com/eedevops/alpine_issue_collector/model"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	ARCHIVEFILE   = "data/cve.xml.gz"
	EXTRACTEDFILE = "data/cve.xml"
	GOVCVEURL     = "http://static.nvd.nist.gov/feeds/xml/cve/nvdcve-2.0-%s.xml.gz"
)

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
		for _, product := range entry.Products.ProductStrings {
			words := strings.Split(product, ":")
			afflicted_software := model.SoftwarePackage{}
			afflicted_software.Name = words[3]
			if len(words) > 4 {
				afflicted_software.Version = words[4]
			} else {
				afflicted_software.Version = "unknown"
			}

			nvd.Entries[i].Packages = append(nvd.Entries[i].Packages, afflicted_software)
		}
	}
	return nvd.Entries, nil
}
func DownloadAndExtractFile(archiveFile, extractedFile string, url string) (string, error) {

	// Create the file
	out, err := os.Create(archiveFile)
	if err != nil {
		return "", err
	}
	defer out.Close()

	// Get the data
	df := GetDataFeedNames()
	for _, de := range df {
		resp, err := http.Get(fmt.Sprintf(GOVCVEURL, de))
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()

		// Writer the body to file
		fmt.Printf("Processing GOV page %s\n", fmt.Sprintf(GOVCVEURL, de))
		_, err = io.Copy(out, resp.Body)
		if err != nil {
			return "", err
		}
	}
	// open archive file
	reader, err := os.Open(archiveFile)
	if err != nil {
		return "", err
	}
	defer reader.Close()

	archive, err := gzip.NewReader(reader)
	if err != nil {
		return "", err
	}
	defer archive.Close()
	//extract archive
	extractedFile = filepath.Join(extractedFile, archive.Name)
	writer, err := os.Create(extractedFile)
	if err != nil {
		return "", err
	}
	defer writer.Close()

	_, err = io.Copy(writer, archive)
	if err != nil {
		return "", err
	}
	// remove tha archive file and return the extracted file
	os.Remove(archiveFile)
	return extractedFile, nil
}
