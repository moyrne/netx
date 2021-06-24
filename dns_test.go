package netx

import (
	"fmt"
	"testing"
)

func TestLookUp(t *testing.T) {
	if _, err := LookUp("10.8.4.200:53", "www.baidu.com"); err != nil {
		fmt.Println("[err]", err)
		return
	}
}
