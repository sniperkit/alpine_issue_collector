package uploaders_test

import (
	"encoding/json"
	"fmt"
	gen "github.com/Pallinder/go-randomdata"
	"io/ioutil"
	"time"
)

func writeMockJsonFile() (time.Time, string, error) {
	now := time.Now()

	name := gen.FullName(gen.RandomGender)
	timeString := now.String()
	timestamp := now.Unix()

	mockMap := map[string]string{
		"name":      name,
		"timestamp": timeString,
	}

	tempFilepath := fmt.Sprintf("/tmp/alpine-collector-uploader-mock-json-%d.json", timestamp)
	jsonData, err := json.MarshalIndent(mockMap, "", "  ")

	if err != nil {
		return now, "", err
	}

	err2 := ioutil.WriteFile(tempFilepath, jsonData, 0644)

	if err2 != nil {
		return now, "", err
	}

	return now, tempFilepath, nil
}
