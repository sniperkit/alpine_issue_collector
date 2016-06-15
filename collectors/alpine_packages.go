package collectors

import (
	"fmt"
	"github.com/PuerkitoBio/goquery"
	"github.com/headzoo/surf"
	"github.com/headzoo/surf/browser"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	DEFAULT_PAGE_URL        = "https://pkgs.alpinelinux.org/packages?page="
	DEFAULT_MAX_CONCURRENCY = 8
)

type AlpinePackageCollector struct {
	bow                *browser.Browser
	maximumConcurrency int
	maxNumberPages     int
}

func NewAlpinePackageCollector(browser *browser.Browser, maximumConcurrency int, maxNumberPages int) *AlpinePackageCollector {
	return &AlpinePackageCollector{
		bow:                browser,
		maximumConcurrency: maximumConcurrency,
		maxNumberPages:     maxNumberPages,
	}
}

func NewDefaultAlpinePackageCollector() *AlpinePackageCollector {
	c := NewAlpinePackageCollector(surf.NewBrowser(), DEFAULT_MAX_CONCURRENCY, 0)
	return c
}

func (c *AlpinePackageCollector) SetMaxNumberPages(maxNumberPages int) {
	c.maxNumberPages = maxNumberPages
}

type AlpinePackage map[string]string
type AlpinePackageDictionary map[string][]AlpinePackage

func (c *AlpinePackageCollector) Collect(verbose bool) (AlpinePackageDictionary, error) {
	c.bow = surf.NewBrowser()
	err := c.bow.Open("https://pkgs.alpinelinux.org/packages")
	if err != nil {
		panic(err)
	}

	// Outputs: "The Go Programming Language"
	fmt.Println(c.bow.Title())

	totalNumberPages := 0
	c.bow.Find("a:contains('»')").Each(func(_ int, s *goquery.Selection) {
		fmt.Println(s.Text())
		attr, exists := s.Attr("href")
		if !exists {
			return
		}
		fmt.Println(attr)
		totalPagesKey := "totalPages"
		regexString := `/packages\?page=(?P<` + totalPagesKey + `>[0-9]+)$`
		re := regexp.MustCompile(regexString)
		names := re.SubexpNames()
		myMap := map[string]string{}
		for i, match := range re.FindStringSubmatch(attr) {
			myMap[names[i]] = match
		}

		fmt.Println(myMap[totalPagesKey])
		totalNumberPages, err = strconv.Atoi(myMap[totalPagesKey])

		if err != nil {
			fmt.Printf("Error parsing the total number of pages %s\n", myMap[totalPagesKey])
			return
		}
	})

	startTime := time.Now()

	pagesUrl := []string{}

	if c.maxNumberPages > 0 {
		totalNumberPages = c.maxNumberPages
	}

	pageChannels := make(chan AlpinePackageDictionary, totalNumberPages)

	for i := 0; i < totalNumberPages; i++ {

		pageNumber := i + 1
		pageUrl := fmt.Sprintf("%s%d", DEFAULT_PAGE_URL, pageNumber)
		if verbose {
			fmt.Printf("Getting page %s\n", pageUrl)
		}
		pagesUrl = append(pagesUrl, pageUrl)
	}

	wg := sync.WaitGroup{}
	throttleChannel := make(chan bool, 8)

	for i, pageUrl := range pagesUrl {
		wg.Add(1)
		throttleChannel <- true
		if verbose {
			fmt.Printf("Executing page %d %s\n", i, pageUrl)
		}
		go func() {
			defer wg.Done()
			pageChannels <- c.getPagePackages(pageUrl)
			<-throttleChannel
		}()
	}

	wg.Wait()

	endTime := time.Now()

	// 3.6 minutes
	timeElapsed := endTime.Sub(startTime)

	fmt.Printf("Time elapsed %f seconds.\n", timeElapsed.Seconds())

	close(pageChannels)

	allPackages := AlpinePackageDictionary{}
	for result := range pageChannels {
		for key, value := range result {
			allPackages[key] = value
		}
	}

	fmt.Printf("Received %d packages\n", len(allPackages))

	return allPackages, nil
}

func (c *AlpinePackageCollector) getPagePackages(pageUrl string) AlpinePackageDictionary {

	err := c.bow.Open(pageUrl)

	if err != nil {
		fmt.Printf("Error collecting page %s", pageUrl)
	}

	allPackageIndex := AlpinePackageDictionary{}
	c.bow.Find("tr").Each(func(_ int, s *goquery.Selection) {
		alpinePackage := AlpinePackage{}
		s.Find("td").Each(func(_ int, t *goquery.Selection) {
			attr, found := t.Attr("class")

			if !found {
				fmt.Println("Could not get class attr")
				return
			}

			value := strings.Replace(strings.Replace(t.Text(), " ", "", -1), "\n", "", -1)
			// If we find a version, split it since alpine uses a composite version + release label
			if attr == "version" {
				parts := strings.Split(value, "-")
				if len(parts) == 2 {
					alpinePackage["version_release"] = parts[1]
					value = parts[0]
				} else {
					alpinePackage["version_release"] = ""
				}
			}
			alpinePackage[attr] = value
		})

		key := alpinePackage["package"]
		if key != "" {
			if _, ok := allPackageIndex[key]; ok {
				allPackageIndex[key] = append(allPackageIndex[key], alpinePackage)
			} else {
				allPackageIndex[key] = []AlpinePackage{alpinePackage}
			}
		}
	})

	return allPackageIndex

}
