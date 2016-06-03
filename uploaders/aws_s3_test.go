package uploaders_test

import "testing"
import (
	"fmt"
	"github.com/eedevops/alpine_issue_collector/uploaders"
	. "github.com/smartystreets/goconvey/convey"
	"os"
)

// Note: you need to set AWS_TEST_BUCKET_NAME in your environment.
// TODO: test error scenario (not credentials)

func TestAwsS3Upload(t *testing.T) {

	testBucketName := os.Getenv("AWS_TEST_BUCKET_NAME")
	Convey("Given that we have a valid AWS S3 account and crendentials", t, func() {
		s3Uploader := uploaders.NewAwsS3Uploader()
		So(testBucketName, ShouldNotBeBlank)
		Convey("And given that we have a valid json file to upload", func() {
			now, filePath, err := writeMockJsonFile()

			So(err, ShouldBeNil)
			So(filePath, ShouldNotBeBlank)

			Convey("We should be able to upload a file to S3", func() {
				key := fmt.Sprintf("alpine_data_collector_test_json-%d.json", now.Unix())
				err := s3Uploader.Upload(filePath, testBucketName, key)
				So(err, ShouldBeNil)

				Convey("And we should be able to cleanup file from AWS S3", func() {
					err := s3Uploader.RemoveFileFromS3(testBucketName, key)

					So(err, ShouldBeNil)

					Convey("And we should be able to cleanup file from local env", func() {
						err := os.RemoveAll(filePath)
						So(err, ShouldBeNil)
					})
				})

			})
		})

	})
}
