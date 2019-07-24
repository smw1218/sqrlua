package sqrlua

import (
	"fmt"
	"log"

	ssp "github.com/smw1218/sqrl-ssp"
)

func TIFCompare(expected, actual uint32) []error {
	diff := expected ^ actual
	log.Printf("diff: %x", diff)
	errors := make([]error, 0)
	var i uint32
	for i = 0; i < 32; i++ {
		mask := uint32(1) << i
		single := mask & diff
		desc := ssp.TIFDesc[single]
		if desc != "" {
			errors = append(errors, fmt.Errorf("%s is %t expected %t", desc, actual&single != 0, expected&single != 0))
		}
	}
	if len(errors) == 0 {
		return nil
	}
	return errors

}
