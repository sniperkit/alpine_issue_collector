/*
Sniperkit-Bot
- Status: analyzed
*/

package model

type AlpinePackageVersionDetails struct {
	Arch       string `json:"arch"`
	Bdate      string `json:"bdate"`
	Branch     string `json:"branch"`
	License    string `json:"license"`
	Maintainer string `json:"maintainer"`
	Package    string `json:"package"`
	Repo       string `json:"repo"`
	Url        string `json:"url"`
	Version    string `json:"version"`
}
