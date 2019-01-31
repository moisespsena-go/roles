package roles

// Roler Roler interface
type Roler interface {
	GetRoles() []string
}

// LocalRoleExtender Local role extender interface
type LocalRoleExtender interface {
	ExtendLocalRoles(role ...string)
}
