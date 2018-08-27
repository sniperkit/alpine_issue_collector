/*
Sniperkit-Bot
- Status: analyzed
*/

package uploaders

// TODO: refactor uploaders to use a common interface
type Uploader interface {
	Upload(params ...string)
}
