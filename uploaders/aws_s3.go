/*
Sniperkit-Bot
- Status: analyzed
*/

package uploaders

import (
	"errors"
	"fmt"
	"os"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
)

var (
	ErrAcquiringAwsS3EnvVars    = errors.New("You need to export the AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, and AWS_REGION env vars.")
	ErrMissingUploadInputParams = errors.New("You need to pass the filePath to upload and the target s3 bucketName and key.")
)

type AwsS3Uploader struct {
	AwsAccessKey       string
	AwsSecretAccessKey string
	s3Session          *s3.S3
	awsSession         *session.Session
	uploader           *s3manager.Uploader
}

func NewAwsS3Uploader() *AwsS3Uploader {
	return &AwsS3Uploader{}
}

func (u *AwsS3Uploader) Upload(filePath, bucketName, key string) error {

	if err := u.createSession(); err != nil {
		fmt.Printf("Could not create session = %s", err.Error())
		return err
	}

	if err := u.listBuckets(); err != nil {
		fmt.Printf("Could not list buckets = %s", err.Error())
		return err
	}

	if _, err := u.uploadFileToS3(filePath, bucketName, key); err != nil {
		fmt.Printf("Could not list buckets = %s", err.Error())
		return err
	}

	return nil
}

func (u *AwsS3Uploader) createSession() error {
	id := os.Getenv("AWS_ACCESS_KEY_ID")
	secret := os.Getenv("AWS_SECRET_ACCESS_KEY")
	region := os.Getenv("AWS_REGION")

	if id == "" || secret == "" || region == "" {
		return ErrAcquiringAwsS3EnvVars
	}
	u.awsSession = session.New(&aws.Config{})
	u.s3Session = s3.New(u.awsSession)
	return nil
}

func (u *AwsS3Uploader) listBuckets() error {
	result, err := u.s3Session.ListBuckets(&s3.ListBucketsInput{})

	if err != nil {
		fmt.Println("Failed to list buckets")
		return err
	}

	fmt.Println("Buckets: ")

	for _, bucket := range result.Buckets {
		fmt.Printf("%s : %s \n", aws.StringValue(bucket.Name), bucket.CreationDate)
	}

	return nil
}

func (u *AwsS3Uploader) uploadFileToS3(fileName, bucketName, key string) (string, error) {

	if fileName == "" || bucketName == "" || key == "" {
		return "", ErrMissingUploadInputParams
	}

	file, err := os.Open(fileName)

	if err != nil {
		return "", err
	}

	defer file.Close()

	params := &s3manager.UploadInput{
		Body:   file,
		Bucket: aws.String(bucketName),
		Key:    aws.String(key),
	}
	u.uploader = s3manager.NewUploader(u.awsSession)
	result, err := u.uploader.Upload(params)

	if err != nil {
		return "", err
	}

	return result.Location, nil
}

func (u *AwsS3Uploader) RemoveFileFromS3(bucketName, key string) error {
	_, err := u.s3Session.DeleteObject(
		&s3.DeleteObjectInput{
			Bucket: aws.String(bucketName),
			Key:    aws.String(key),
		},
	)

	if err != nil {
		return err
	}

	return nil
}
