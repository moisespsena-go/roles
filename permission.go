package roles

import (
	"errors"
	"fmt"
)

const (
	GlobalGroup = ""

	LNone = 0
	// Create predefined permission mode, create permission
	LCreate = 1
	// Read predefined permission mode, read permission
	LRead = 2
	// Update predefined permission mode, update permission
	LUpdate = LRead | 4
	// Delete predefined permission mode, deleted permission
	LDelete = LRead | 8
	// CRUD predefined permission mode, create+read+update+delete permission
	LCRUD = LCreate | LRead | LUpdate | LDelete
)

var (
	// Create predefined permission mode, create permission
	Create = PermissionMode{GlobalGroup, "create", LCreate}
	// Read predefined permission mode, read permission
	Read = PermissionMode{GlobalGroup, "read", LRead}
	// Update predefined permission mode, update permission
	Update = PermissionMode{GlobalGroup, "update", LUpdate}
	// Delete predefined permission mode, deleted permission
	Delete = PermissionMode{GlobalGroup, "delete", LDelete}
	// CRUD predefined permission mode, create+read+update+delete permission
	CRUD = PermissionMode{GlobalGroup, "crud", LCRUD}
)

// ErrPermissionDenied no permission error
var ErrPermissionDenied = errors.New("permission denied")

// Permission a struct contains permission definitions
type Permission struct {
	Role               *Role
	AllowedRoles       map[PermissionMode][]string
	DeniedRoles        map[PermissionMode][]string
	DaniedAnotherRoles map[PermissionMode][]string
}

func includeRoles(roles []string, values []string) bool {
	for _, role := range roles {
		if role == Anyone {
			return true
		}

		for _, value := range values {
			if value == role {
				return true
			}
		}
	}
	return false
}

// Concat concat two permissions into a new one
func (permission *Permission) Concat(newPermission *Permission) *Permission {
	var result = Permission{
		Role:               Global,
		AllowedRoles:       map[PermissionMode][]string{},
		DeniedRoles:        map[PermissionMode][]string{},
		DaniedAnotherRoles: map[PermissionMode][]string{},
	}

	var appendRoles = func(p *Permission) {
		if p != nil {
			result.Role = p.Role

			for mode, roles := range p.AllowedRoles {
				result.AllowedRoles[mode] = append(result.AllowedRoles[mode], roles...)
			}

			for mode, roles := range p.DeniedRoles {
				result.DeniedRoles[mode] = append(result.DeniedRoles[mode], roles...)
			}

			for mode, roles := range p.DaniedAnotherRoles {
				result.DaniedAnotherRoles[mode] = append(result.DaniedAnotherRoles[mode], roles...)
			}
		}
	}

	appendRoles(newPermission)
	appendRoles(permission)
	return &result
}

// Allow allows permission mode for roles
func (permission *Permission) Allow(mode PermissionMode, roles ...string) *Permission {
	if mode == CRUD {
		return permission.Allow(Create, roles...).Allow(Update, roles...).Allow(Read, roles...).Allow(Delete, roles...)
	}

	if permission.AllowedRoles[mode] == nil {
		permission.AllowedRoles[mode] = []string{}
	}
	permission.AllowedRoles[mode] = append(permission.AllowedRoles[mode], roles...)
	return permission
}

// Deny deny permission mode for roles
func (permission *Permission) Deny(mode PermissionMode, roles ...string) *Permission {
	if mode == CRUD {
		return permission.Deny(Create, roles...).Deny(Update, roles...).Deny(Read, roles...).Deny(Delete, roles...)
	}

	if permission.DeniedRoles[mode] == nil {
		permission.DeniedRoles[mode] = []string{}
	}
	permission.DeniedRoles[mode] = append(permission.DeniedRoles[mode], roles...)
	return permission
}

// DenyAnother deny another roles for permission mode
func (permission *Permission) DenyAnother(mode PermissionMode, roles ...string) *Permission {
	if mode == CRUD {
		return permission.Allow(Create, roles...).Allow(Update, roles...).Allow(Read, roles...).Allow(Delete, roles...)
	}

	if permission.DaniedAnotherRoles[mode] == nil {
		permission.DaniedAnotherRoles[mode] = []string{}
	}
	permission.DaniedAnotherRoles[mode] = append(permission.DaniedAnotherRoles[mode], roles...)
	return permission
}

// HasPermissionS check roles strings has permission for mode or not
func (permission Permission) HasPermissionS(mode PermissionMode, roles ...string) bool {
	rolesi := make([]interface{}, len(roles))
	for i, v := range roles {
		rolesi[i] = v
	}
	return permission.HasPermission(mode, rolesi...)
}

// HasPermission check roles has permission for mode or not
func (permission Permission) HasPermission(mode PermissionMode, roles ...interface{}) bool {
	var roleNames []string
	for _, role := range roles {
		if r, ok := role.(string); ok {
			roleNames = append(roleNames, r)
		} else if roler, ok := role.(Roler); ok {
			roleNames = append(roleNames, roler.GetRoles()...)
		} else {
			fmt.Printf("invalid role %#v\n", role)
			return false
		}
	}

	if len(permission.DaniedAnotherRoles) != 0 {
		if roles := permission.DaniedAnotherRoles[mode]; roles != nil {
			if !includeRoles(roles, roleNames) {
				return false
			}
		}
	}

	if len(permission.DeniedRoles) != 0 {
		if DeniedRoles := permission.DeniedRoles[mode]; DeniedRoles != nil {
			if includeRoles(DeniedRoles, roleNames) {
				return false
			}
		}
	}

	// return true if haven't define allowed roles
	if len(permission.AllowedRoles) == 0 {
		return true
	}

	if AllowedRoles := permission.AllowedRoles[mode]; AllowedRoles != nil {
		if includeRoles(AllowedRoles, roleNames) {
			return true
		}
	}

	return false
}
