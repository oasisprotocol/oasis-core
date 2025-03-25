package volume

// Volume is a persistent volume.
type Volume struct {
	// ID is the unique volume identifier.
	ID string
	// Path is the absolute path to the volume file.
	Path string
	// Labels are the labels assigned to the volume.
	Labels map[string]string
}

// HasLabels returns true iff the volume has all of the given labels set.
func (v *Volume) HasLabels(labels map[string]string) bool {
	for key, value := range labels {
		if ev, ok := v.Labels[key]; !ok || ev != value {
			return false
		}
	}
	return true
}

// Descriptor is a serializable volume descriptor.
type Descriptor struct {
	// ID is the unique volume identifier.
	ID string `json:"id"`
	// Labels are the labels assigned to the volume.
	Labels map[string]string `json:"labels"`
}
