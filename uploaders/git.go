package uploaders

import (
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strings"
)

const (
	CONFIG_FILE_HEADER      = "Added by ILM Git uploader"
	DEFAULT_GIT_REMOTE_HOST = "github.com"
)

type GitServerUploader struct {
}

var (
	ErrSshDeployKeyNotPassed = errors.New("SSH Deploy Key not passed as parameter")
	ErrHomeEnvVarNotSet      = errors.New("$HOME env var not set, this is needed for deploying key.")
	ErrSshKeyScan            = errors.New("Could not scan or retrieve ssh key")
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

	sshDir := fmt.Sprintf("%s/.ssh", homePath)
	if err := mkdir(sshDir); err != nil {
		return err
	}

	defaultDeployKeyFile := fmt.Sprintf("%s/auto-generated-ilm-deploy-key", sshDir)

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

	// Add host's ssh key into trusted known hosts file
	knownHosts := fmt.Sprintf("%s/known_hosts", sshDir)

	dataString = ""
	if _, err := os.Stat(knownHosts); os.IsNotExist(err) {
		if err := ioutil.WriteFile(knownHosts, []byte(dataString), 0600); err != nil {
			return err
		}
	} else {
		data, err := ioutil.ReadFile(knownHosts)
		if err != nil {
			fmt.Errorf("Could not read config file %s", knownHosts)
			return err
		}
		dataString = string(data)
	}

	if !strings.Contains(dataString, DEFAULT_GIT_REMOTE_HOST) {
		// TODO: create a backup copy of the file
		f, err := os.OpenFile(knownHosts, os.O_APPEND|os.O_WRONLY, 0600)

		if err != nil {
			return err
		}

		defer f.Close()

		sshScanResult, _, err := sshKeyScan(DEFAULT_GIT_REMOTE_HOST)

		if _, err = f.WriteString(sshScanResult); err != nil {
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

func sshKeyScan(host string) (string, string, error) {
	result, err := exec.Command("ssh-keyscan", "-t", "ssh-rsa", host).Output()
	sshKeyValue := ""
	sshScanResult := ""
	if err != nil {
		fmt.Println("Error with ssh-keyscan.")
		fmt.Printf("%s", err.Error())
		return sshScanResult, sshKeyValue, err
	}

	sshKeyName := "sshKey"
	regExpString := fmt.Sprintf("%s\\sssh-rsa\\s(?P<%s>[[:graph:]]+==)", host, sshKeyName)

	re := regexp.MustCompile(regExpString)
	resultString := string(result)
	names := re.SubexpNames()
	myMap := map[string]string{}
	for i, match := range re.FindStringSubmatch(resultString) {
		myMap[names[i]] = match
	}

	sshKeyValue = myMap[sshKeyName]
	sshScanResult = re.FindString(resultString)

	if sshScanResult == "" || sshKeyValue == "" {
		return sshScanResult, sshKeyValue, ErrSshKeyScan
	}

	ipAddress, err := net.ResolveIPAddr("ip", host)

	if err != nil {
		return sshScanResult, sshKeyValue, err
	}

	// Inject ip address for host
	parts := strings.Split(resultString, " ")
	if len(parts) < 3 {
		return sshScanResult, sshKeyValue, err
	}

	sshScanResult = fmt.Sprintf("%s,%s %s %s\n", parts[0], ipAddress, parts[1], parts[2])

	return sshScanResult, sshKeyValue, nil
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
