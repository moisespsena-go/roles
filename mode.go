package roles

import (
	"fmt"
	"strconv"
	"strings"
)

// PermissionMode permission mode. Format [level:4][space][group][space][name]
type PermissionMode struct {
	group string
	name  string
	level int
}

func (r PermissionMode) Level() int {
	return r.level
}

func (r PermissionMode) Name() string {
	return r.name
}

func (r PermissionMode) Accept(level int) bool {
	return (r.level & level) != 0
}

func NewMode(roleName string) (r PermissionMode) {
	var err error
	if r.level, err = strconv.Atoi(strings.TrimLeft(string(roleName[0:4]), "0")); err != nil {
		panic(fmt.Errorf("NewName: parse level failed: %v", err))
	}
	parts := strings.SplitN(roleName[5:], " ", 2)
	r.group, r.name = parts[0], parts[1]
	return
}
