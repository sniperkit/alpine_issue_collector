package uploaders

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"
)

const (
	CONFIG_FILE_HEADER = "Added by ILM Git uploader"
)

type GitServerUploader struct {
}

var (
	ErrSshDeployKeyNotPassed = errors.New("SSH Deploy Key not passed as parameter")
	ErrHomeEnvVarNotSet      = errors.New("$HOME env var not set, this is needed for deploying key.")
)

// TODO: make paths configurable with some default values
func ConfigureSshEnv(deployKey string) error {

	if deployKey == "" {
		return ErrSshDeployKeyNotPassed
	}

	homePath := os.Getenv("HOME")

	if homePath == "" {
		return ErrHomeEnvVarNotSet
	}

	defaultDeployKeyFile := homePath + "/.ssh/auto-generated-ilm-deploy-key"

	if err := ioutil.WriteFile(defaultDeployKeyFile, []byte(deployKey), 0600); err != nil {
		return err
	}

	configFilePath := homePath + "/.ssh/config"

	dataString := ""
	if _, err := os.Stat(configFilePath); os.IsNotExist(err) {
		if err := ioutil.WriteFile(configFilePath, []byte(dataString), 0600); err != nil {
			return err
		}
	} else {
		data, err := ioutil.ReadFile(configFilePath)
		if err != nil {
			fmt.Errorf("Could not read config file %s", configFilePath)
			return err
		}
		dataString = string(data)
	}

	if !strings.Contains(dataString, CONFIG_FILE_HEADER) {
		// TODO: create a backup copy of the file
		f, err := os.OpenFile(configFilePath, os.O_APPEND|os.O_WRONLY, 0600)

		if err != nil {
			return err
		}

		defer f.Close()

		if _, err = f.WriteString(configFileStringBlock(defaultDeployKeyFile)); err != nil {
			return err
		}
	}

	return nil
}

func configFileStringBlock(deployKeyPath string) string {
	pre := fmt.Sprintf("\n#----------- %s ------------\n", CONFIG_FILE_HEADER)
	post := "\n#-------------------------------------------------\n"
	return fmt.Sprintf("%s\nHost github.com\nIdentityFile %s\n%s", pre,
		deployKeyPath,
		post,
	)
}

// TODO: make file paths configurable.
func CleanupSshEnv() error {
	homePath := os.Getenv("HOME")

	if homePath == "" {
		return ErrHomeEnvVarNotSet
	}

	defaultDeployKeyFile := homePath + "/.ssh/auto-generated-ilm-deploy-key"

	err := os.Remove(defaultDeployKeyFile)

	if err != nil {
		fmt.Printf("Could not remove file %s", defaultDeployKeyFile)
	}

	configFilePath := homePath + "/.ssh/config"

	dataString := ""
	if _, err := os.Stat(configFilePath); os.IsNotExist(err) {
		return nil
	} else {
		data, err := ioutil.ReadFile(configFilePath)
		if err != nil {
			fmt.Errorf("Could not read config file %s", configFilePath)
			return err
		}
		dataString = string(data)
	}

	replacedDataString := strings.Replace(dataString, configFileStringBlock(defaultDeployKeyFile), "", -1)

	if err := ioutil.WriteFile(configFilePath, []byte(replacedDataString), 0644); err != nil {
		return err
	}

	return nil
}

func CleanupLocalRepo(repoPath string) error {
	return os.RemoveAll(repoPath)
}

type GitRepoConfig struct {
	RepoPath       string
	BranchName     string
	CommitMsg      string
	RepoRemoteUri  string
	RepoOriginName string
}

func NewGitRepoConfig(repoPath, branchName, commitMsg, repoRemoteUri, RepoOriginName string) *GitRepoConfig {
	return &GitRepoConfig{
		RepoPath:       repoPath,
		BranchName:     branchName,
		CommitMsg:      commitMsg,
		RepoRemoteUri:  repoRemoteUri,
		RepoOriginName: RepoOriginName,
	}
}

func Upload(filePath string, repoConfig GitRepoConfig) error {
	fmt.Println("Uploading")

	repoPath := repoConfig.RepoPath
	remoteRepoUri := repoConfig.RepoRemoteUri
	branchName := repoConfig.BranchName
	sourceFile := filePath
	commitMsg := repoConfig.CommitMsg
	origin := repoConfig.RepoOriginName

	if err := mkdir(repoPath); err != nil {
		return err
	}

	if err := gitStatus(repoPath); err != nil {
		fmt.Printf("No local git repo found in %s, trying to clone...\n", repoPath)

		if err := gitClone(remoteRepoUri, repoPath); err != nil {
			return err
		}
	}

	if err := gitLsRemote(repoPath); err != nil {
		return err
	}

	if err := gitCheckout(repoPath, branchName); err != nil {
		return err
	}

	if err := copyFile(sourceFile, repoPath); err != nil {
		return err
	}

	if err := gitAddAll(repoPath); err != nil {
		return err
	}

	if err := commitAll(repoPath, commitMsg); err != nil {
		return err
	}

	if err := push(repoPath, origin, branchName); err != nil {
		return err
	}

	return nil
}

func mkdir(destinationDir string) error {
	if err := exec.Command("mkdir", "-p", destinationDir).Run(); err != nil {
		fmt.Println("Error making dir.")
		fmt.Printf("%s", err.Error())
		return err
	}
	return nil
}

func gitStatus(repoPath string) error {
	status := exec.Command("git", "status")
	status.Dir = repoPath
	if err := status.Run(); err != nil {
		return err
	}
	return nil
}

func gitClone(repoRemoteUri, repoPath string) error {
	clone := exec.Command("git", "clone", repoRemoteUri, repoPath)
	clone.Dir = repoPath
	if err := clone.Run(); err != nil {
		fmt.Println("Error cloning.")
		fmt.Printf("%s", err.Error())
		return err
	}
	return nil
}

func gitLsRemote(repoPath string) error {
	lsRemote := exec.Command("git", "ls-remote")
	lsRemote.Dir = repoPath
	if err := lsRemote.Run(); err != nil {
		fmt.Printf("%s", err.Error())
		fmt.Println("Error git ls-remote. trying to clone")
		return err
	}
	return nil
}

func gitCheckout(repoPath string, branchName string) error {
	checkout := exec.Command("git", "checkout", branchName)
	checkout.Dir = repoPath
	if err := checkout.Run(); err != nil {
		fmt.Println("Error changing branch.")
		fmt.Printf("%s", err.Error())
		return err
	}
	return nil
}

func copyFile(sourceFile string, destinationDir string) error {
	copyCmd := exec.Command("cp", "-f", sourceFile, ".")
	copyCmd.Dir = destinationDir
	if err := copyCmd.Run(); err != nil {
		fmt.Println("Error copying file.")
		fmt.Printf("%s", err.Error())
		return err
	}
	return nil
}

func gitAddAll(repoPath string) error {
	gitAdd := exec.Command("git", "add", "--all")
	gitAdd.Dir = repoPath
	if err := gitAdd.Run(); err != nil {
		fmt.Println("Error git add --all")
		fmt.Printf("%s", err.Error())
		return err
	}
	return nil
}

func commitAll(repoPath string, commitMsg string) error {
	gitCommit := exec.Command("git", "commit", "-m", commitMsg)
	gitCommit.Dir = repoPath
	if out, err := gitCommit.Output(); err != nil {
		fmt.Println("Error git commit")
		fmt.Printf("%s", err.Error())

		if !strings.Contains(string(out), "nothing to commit, working directory clean") {
			return err
		}

		fmt.Println(string(out))
	}
	return nil
}

func push(repoPath string, remoteOrigin string, branchName string) error {
	gitPush := exec.Command("git", "push", remoteOrigin, branchName)
	gitPush.Dir = repoPath
	if err := gitPush.Run(); err != nil {
		fmt.Println("Error git push")
		fmt.Printf("%s", err.Error())
		return err
	}
	return nil
}
